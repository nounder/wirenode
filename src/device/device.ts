/**
 * WireGuard device: peers, encryption/decryption, and UDP transport.
 */
import { createSocket, Socket as UDPSocket } from "dgram"
import type { RemoteInfo } from "dgram"
import { EventEmitter } from "events"
import * as Curve25519 from "../crypto/Curve25519.ts"
import * as ChaCha20Poly1305 from "../crypto/ChaCha20Poly1305.ts"
import * as Handshake from "../noise/Handshake.ts"
import * as Cookie from "../noise/Cookie.ts"
import { Peer } from "./Peer.ts"
import type { PeerConfig } from "./Peer.ts"

const PADDING_MULTIPLE = 16

export interface DeviceConfig {
  privateKey: Uint8Array // 32 bytes
  listenPort?: number
  peers: PeerConfig[]
  mtu?: number
}

/**
 * WireGuard device.
 *
 * Events:
 * - "packet" (data: Uint8Array, peer: Peer) - decrypted IP packet from a peer
 * - "error" (err: Error) - non-fatal error
 * - "handshakeComplete" (peer: Peer) - handshake completed with a peer
 */
export class Device extends EventEmitter {
  readonly privateKey: Uint8Array
  readonly publicKey: Uint8Array
  readonly mtu: number

  private socket: UDPSocket | null = null
  private peers: Map<string, Peer> = new Map() // publicKeyHex -> Peer
  private indexTable: Map<
    number,
    { peer: Peer; keypair?: Handshake.Keypair; handshake?: Handshake.HandshakeContext }
  > = new Map()
  private cookieGenerators: Map<string, Cookie.CookieGenerator> = new Map() // per peer
  private cookieChecker: Cookie.CookieChecker
  private listenPort: number

  constructor(config: DeviceConfig) {
    super()
    this.privateKey = config.privateKey
    this.publicKey = Curve25519.publicKey(config.privateKey)
    this.mtu = config.mtu ?? 1420
    this.listenPort = config.listenPort ?? 0
    this.cookieChecker = new Cookie.CookieChecker(this.publicKey)

    for (const peerConfig of config.peers) {
      this.addPeer(peerConfig)
    }
  }

  addPeer(config: PeerConfig): Peer {
    const peer = new Peer(config, this.privateKey)
    this.peers.set(peer.publicKeyHex, peer)

    // Cookie generator for this peer
    const cookieGen = new Cookie.CookieGenerator(config.publicKey)
    this.cookieGenerators.set(peer.publicKeyHex, cookieGen)

    // When keypair is ready, flush staged packets
    peer.on("keypairReady", () => {
      this.flushStagedPackets(peer)
      this.emit("handshakeComplete", peer)
    })

    // Keepalive
    peer.on("sendKeepalive", () => {
      this.sendKeepalive(peer)
    })

    return peer
  }

  async up(): Promise<void> {
    return new Promise((resolve) => {
      this.socket = createSocket("udp4")
      this.socket.on("message", (msg, rinfo) => this.handleIncoming(msg, rinfo))
      this.socket.on("error", (err) => this.emit("error", err))
      this.socket.bind(this.listenPort, () => {
        const addr = this.socket!.address()
        this.listenPort = addr.port
        resolve()
      })
    })
  }

  async down(): Promise<void> {
    for (const peer of this.peers.values()) {
      peer.destroy()
    }
    this.peers.clear()
    this.indexTable.clear()
    if (this.socket) {
      return new Promise((resolve) => {
        this.socket!.close(() => resolve())
        this.socket = null
      })
    }
  }

  getPort(): number {
    return this.listenPort
  }

  getPeer(publicKeyHex: string): Peer | undefined {
    return this.peers.get(publicKeyHex)
  }

  getPeers(): Peer[] {
    return [...this.peers.values()]
  }

  initiateHandshake(peer: Peer): void {
    const now = Date.now()
    if (now - peer.lastHandshakeAttempt < 1000) return // rate limit
    peer.lastHandshakeAttempt = now

    try {
      const msg = Handshake.createMessageInitiation(peer.handshake, this.publicKey, this.privateKey)

      // Register local index
      this.indexTable.set(peer.handshake.localIndex, { peer, handshake: peer.handshake })

      // Add MACs
      const cookieGen = this.cookieGenerators.get(peer.publicKeyHex)
      if (cookieGen) cookieGen.addMacs(msg)

      this.sendToEndpoint(peer, msg)
    } catch (err) {
      this.emit("error", err)
    }
  }

  sendPacket(peer: Peer, data: Uint8Array): void {
    // Check for valid keypair
    if (peer.needsRekey()) {
      peer.stagedPackets.push(data)
      if (peer.stagedPackets.length > 128) peer.stagedPackets.shift()
      this.initiateHandshake(peer)
      return
    }

    const keypair = peer.getSendKeypair()
    if (!keypair) {
      peer.stagedPackets.push(data)
      if (peer.stagedPackets.length > 128) peer.stagedPackets.shift()
      this.initiateHandshake(peer)
      return
    }

    this.encryptAndSend(peer, keypair, data)
  }

  private encryptAndSend(peer: Peer, keypair: Handshake.Keypair, plaintext: Uint8Array): void {
    const nonce = keypair.sendNonce++

    if (nonce >= Handshake.RejectAfterMessages) {
      this.initiateHandshake(peer)
      return
    }

    // Pad to PADDING_MULTIPLE
    const paddedLen =
      plaintext.length > 0 ? (plaintext.length + PADDING_MULTIPLE - 1) & ~(PADDING_MULTIPLE - 1) : 0
    const padded = new Uint8Array(paddedLen)
    padded.set(plaintext)

    // Build nonce (12 bytes: 4 zero + 8 counter LE)
    const nonceBytes = new Uint8Array(12)
    const nonceView = new DataView(nonceBytes.buffer)
    // Write nonce as little-endian uint64 at offset 4
    nonceView.setUint32(4, nonce >>> 0, true)
    nonceView.setUint32(8, (nonce / 0x100000000) >>> 0, true)

    // Encrypt
    const encrypted = ChaCha20Poly1305.seal(keypair.sendKey, nonceBytes, padded)

    // Build transport message
    const msg = new Uint8Array(Handshake.MessageTransportHeaderSize + encrypted.length)
    const view = new DataView(msg.buffer)
    view.setUint32(0, Handshake.MessageTransportType, true)
    view.setUint32(Handshake.MessageTransportOffsetReceiver, keypair.remoteIndex, true)
    view.setUint32(Handshake.MessageTransportOffsetCounter, nonce >>> 0, true)
    view.setUint32(Handshake.MessageTransportOffsetCounter + 4, (nonce / 0x100000000) >>> 0, true)
    msg.set(encrypted, Handshake.MessageTransportOffsetContent)

    this.sendToEndpoint(peer, msg)
    peer.lastSentPacket = Date.now()
  }

  private sendKeepalive(peer: Peer): void {
    const keypair = peer.getSendKeypair()
    if (!keypair) return
    this.encryptAndSend(peer, keypair, new Uint8Array(0))
  }

  private flushStagedPackets(peer: Peer): void {
    const packets = peer.stagedPackets
    peer.stagedPackets = []
    for (const pkt of packets) {
      this.sendPacket(peer, pkt)
    }
    peer.startKeepalive()
  }

  private handleIncoming(buf: Buffer, rinfo: RemoteInfo): void {
    const msg = new Uint8Array(buf)
    if (msg.length < 4) return

    const msgType = new DataView(msg.buffer, msg.byteOffset, msg.byteLength).getUint32(0, true)

    switch (msgType) {
      case Handshake.MessageInitiationType:
        this.handleInitiation(msg, rinfo)
        break
      case Handshake.MessageResponseType:
        this.handleResponse(msg, rinfo)
        break
      case Handshake.MessageCookieReplyType:
        this.handleCookieReply(msg, rinfo)
        break
      case Handshake.MessageTransportType:
        this.handleTransport(msg, rinfo)
        break
    }
  }

  private handleInitiation(msg: Uint8Array, rinfo: RemoteInfo): void {
    if (msg.length !== Handshake.MessageInitiationSize) return

    // Verify MAC1
    if (!this.cookieChecker.checkMAC1(msg)) return

    const result = Handshake.consumeMessageInitiation(msg, this.publicKey, this.privateKey, (pk) =>
      this.lookupPeerByPublicKey(pk),
    )

    if (!result) return

    const peer = result.peer
    // Find the actual Peer object
    const peerObj = this.findPeerByHandshake(peer)
    if (!peerObj) return

    // Update endpoint
    peerObj.endpoint = `${rinfo.address}:${rinfo.port}`

    // Create response
    try {
      const response = Handshake.createMessageResponse(peer)

      // Register index
      this.indexTable.set(peer.localIndex, { peer: peerObj, handshake: peer })

      // Add MACs
      const cookieGen = this.cookieGenerators.get(peerObj.publicKeyHex)
      if (cookieGen) cookieGen.addMacs(response)

      this.sendToEndpoint(peerObj, response)

      // Derive session keys
      peerObj.activateKeypair()

      // Register keypair index
      if (peerObj.nextKeypair) {
        this.indexTable.set(peerObj.nextKeypair.localIndex, {
          peer: peerObj,
          keypair: peerObj.nextKeypair,
        })
      }
      if (peerObj.currentKeypair) {
        this.indexTable.set(peerObj.currentKeypair.localIndex, {
          peer: peerObj,
          keypair: peerObj.currentKeypair,
        })
      }
    } catch (err) {
      this.emit("error", err)
    }
  }

  private handleResponse(msg: Uint8Array, rinfo: RemoteInfo): void {
    if (msg.length !== Handshake.MessageResponseSize) return

    // Verify MAC1
    if (!this.cookieChecker.checkMAC1(msg)) return

    const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength)
    const receiverIndex = view.getUint32(8, true)

    const entry = this.indexTable.get(receiverIndex)
    if (!entry?.peer) return

    const peer = entry.peer
    const ok = Handshake.consumeMessageResponse(msg, peer.handshake, this.privateKey)
    if (!ok) return

    // Update endpoint
    peer.endpoint = `${rinfo.address}:${rinfo.port}`

    // Derive session keys
    peer.activateKeypair()

    // Register keypair indices
    if (peer.currentKeypair) {
      this.indexTable.set(peer.currentKeypair.localIndex, { peer, keypair: peer.currentKeypair })
    }
    if (peer.previousKeypair) {
      this.indexTable.set(peer.previousKeypair.localIndex, { peer, keypair: peer.previousKeypair })
    }

    // Send keepalive to confirm
    this.sendKeepalive(peer)
  }

  private handleCookieReply(msg: Uint8Array, _rinfo: RemoteInfo): void {
    if (msg.length !== Handshake.MessageCookieReplySize) return

    const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength)
    const receiverIndex = view.getUint32(4, true)

    const entry = this.indexTable.get(receiverIndex)
    if (!entry?.peer) return

    const cookieGen = this.cookieGenerators.get(entry.peer.publicKeyHex)
    if (cookieGen) cookieGen.consumeReply(msg)
  }

  private handleTransport(msg: Uint8Array, rinfo: RemoteInfo): void {
    if (msg.length < Handshake.MessageTransportHeaderSize + 16) return // header + poly1305 tag

    const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength)
    const receiverIndex = view.getUint32(Handshake.MessageTransportOffsetReceiver, true)
    const counterLow = view.getUint32(Handshake.MessageTransportOffsetCounter, true)
    const counterHigh = view.getUint32(Handshake.MessageTransportOffsetCounter + 4, true)
    const counter = counterLow + counterHigh * 0x100000000

    // Lookup keypair
    const entry = this.indexTable.get(receiverIndex)
    if (!entry?.peer) return

    const peer = entry.peer
    const keypair = entry.keypair ?? peer.findKeypairByIndex(receiverIndex)
    if (!keypair) return

    // Check keypair validity
    if (Date.now() - keypair.created > Handshake.RejectAfterTime) return

    // Replay check
    if (!keypair.replayFilter.validateCounter(counter, Handshake.RejectAfterMessages)) return

    // Build nonce
    const nonceBytes = new Uint8Array(12)
    const nonceView = new DataView(nonceBytes.buffer)
    nonceView.setUint32(4, counterLow, true)
    nonceView.setUint32(8, counterHigh, true)

    // Decrypt
    const ciphertext = msg.subarray(Handshake.MessageTransportOffsetContent)
    const plaintext = ChaCha20Poly1305.open(keypair.receiveKey, nonceBytes, ciphertext)
    if (!plaintext) return

    // Update endpoint
    peer.endpoint = `${rinfo.address}:${rinfo.port}`
    peer.lastReceivedPacket = Date.now()

    // Promote next keypair if needed
    if (peer.nextKeypair === keypair) {
      peer.receivedWithKeypair(keypair)
    }

    // Emit decrypted packet (skip keepalives = empty packets)
    if (plaintext.length > 0) {
      // Use IP total length to determine actual packet size (WireGuard pads to 16-byte boundary)
      let end = plaintext.length
      if (plaintext.length >= 4) {
        const version = (plaintext[0]! >> 4) & 0xf
        if (version === 4) {
          // IPv4: total length at offset 2-3
          const totalLen = (plaintext[2]! << 8) | plaintext[3]!
          if (totalLen > 0 && totalLen <= plaintext.length) {
            end = totalLen
          }
        } else if (version === 6 && plaintext.length >= 40) {
          // IPv6: payload length at offset 4-5 + 40 byte header
          const payloadLen = (plaintext[4]! << 8) | plaintext[5]!
          const totalLen = 40 + payloadLen
          if (totalLen > 0 && totalLen <= plaintext.length) {
            end = totalLen
          }
        }
      }
      this.emit("packet", plaintext.subarray(0, end), peer)
    }
  }

  private sendToEndpoint(peer: Peer, data: Uint8Array): void {
    if (!peer.endpoint || !this.socket) return

    const [host, portStr] = peer.endpoint.split(":")
    const port = parseInt(portStr!, 10)
    if (!host || isNaN(port)) return

    this.socket.send(Buffer.from(data), port, host, (err) => {
      if (err) this.emit("error", err)
    })
  }

  private lookupPeerByPublicKey(pk: Uint8Array): Handshake.HandshakeContext | null {
    const hex = Buffer.from(pk).toString("hex")
    const peer = this.peers.get(hex)
    return peer?.handshake ?? null
  }

  private findPeerByHandshake(hs: Handshake.HandshakeContext): Peer | null {
    for (const peer of this.peers.values()) {
      if (peer.handshake === hs) return peer
    }
    return null
  }
}
