/**
 * WireGuard device: peers, encryption/decryption, and UDP transport.
 */
import * as NDgram from "node:dgram"
import * as Curve25519 from "../crypto/Curve25519.ts"
import * as ChaCha20Poly1305 from "../crypto/ChaCha20Poly1305.ts"
import * as Handshake from "../noise/Handshake.ts"
import * as Cookie from "../noise/Cookie.ts"
import * as Peer from "./Peer.ts"
import * as TypedEmitter from "../util/TypedEmitter.ts"
import type * as TcpStack from "../net/TcpStack.ts"
import * as Result from "../Result.ts"

const PADDING_MULTIPLE = 16

export interface DeviceConfig {
  privateKey: Uint8Array // 32 bytes
  listenPort?: number
  peers: Peer.PeerConfig[]
  mtu?: number
}

export type DeviceEvents = {
  packet: [data: Uint8Array, peer: Peer.Peer]
  handshakeComplete: [peer: Peer.Peer]
  error: [err: Error]
}

interface IndexEntry {
  peer: Peer.Peer
  keypair?: Handshake.Keypair
  handshake?: Handshake.HandshakeContext
}

export interface Device {
  events: TypedEmitter.TypedEmitter<DeviceEvents>

  readonly privateKey: Uint8Array
  readonly publicKey: Uint8Array
  readonly mtu: number

  socket: NDgram.Socket | null
  peers: Map<string, Peer.Peer>
  indexTable: Map<number, IndexEntry>
  cookieGenerators: Map<string, Cookie.CookieGenerator>
  cookieChecker: Cookie.CookieChecker
  listenPort: number
}

export type DeviceResource = Device & AsyncDisposable

export function open(config: DeviceConfig): Promise<Result.Result<DeviceResource>> {
  const publicKey = Curve25519.publicKey(config.privateKey)
  const self: Device = {
    events: TypedEmitter.make<DeviceEvents>(),
    privateKey: config.privateKey,
    publicKey,
    mtu: config.mtu ?? 1420,
    socket: null,
    peers: new Map(),
    indexTable: new Map(),
    cookieGenerators: new Map(),
    cookieChecker: new Cookie.CookieChecker(publicKey),
    listenPort: config.listenPort ?? 0,
  }

  for (const peerConfig of config.peers) {
    addPeer(self, peerConfig)
  }

  return new Promise((resolve) => {
    const socket = NDgram.createSocket("udp4")
    self.socket = socket
    socket.on("message", (msg, rinfo) => handleIncoming(self, msg, rinfo))
    socket.once("error", (err) => {
      self.socket = null
      resolve(Result.error(err))
    })
    socket.bind(self.listenPort, () => {
      socket.removeAllListeners("error")
      socket.on("error", (err) => self.events.emit("error", err))
      const addr = socket.address()
      self.listenPort = addr.port
      const resource = Object.create(self, {
        [Symbol.asyncDispose]: { value: () => close(self) },
      }) as DeviceResource
      resolve(Result.ok(resource))
    })
  })
}

export function addPeer(self: Device, config: Peer.PeerConfig): Peer.Peer {
  const peer = Peer.make(config, self.privateKey)
  self.peers.set(peer.publicKeyHex, peer)

  const cookieGen = new Cookie.CookieGenerator(config.publicKey)
  self.cookieGenerators.set(peer.publicKeyHex, cookieGen)

  peer.events.on("keypairReady", () => {
    flushStagedPackets(self, peer)
    self.events.emit("handshakeComplete", peer)
  })

  peer.events.on("sendKeepalive", () => {
    sendKeepalive(self, peer)
  })

  return peer
}

export async function close(self: Device): Promise<void> {
  for (const peer of self.peers.values()) {
    Peer.destroy(peer)
  }
  self.peers.clear()
  self.indexTable.clear()
  if (self.socket) {
    const socket = self.socket
    self.socket = null
    return new Promise((resolve) => {
      socket.close(() => resolve())
    })
  }
}

export function getPort(self: Device): number {
  return self.listenPort
}

export function getPeer(self: Device, publicKeyHex: string): Peer.Peer | undefined {
  return self.peers.get(publicKeyHex)
}

export function getPeers(self: Device): Peer.Peer[] {
  return [...self.peers.values()]
}

export function asTransport(self: Device): TcpStack.PacketTransport {
  return {
    events: self.events,
    sendPacket: (peer, data) => sendPacket(self, peer, data),
    getPeers: () => getPeers(self),
  }
}

export function initiateHandshake(self: Device, peer: Peer.Peer): void {
  const now = Date.now()
  if (now - peer.lastHandshakeAttempt < 1000) return // rate limit
  peer.lastHandshakeAttempt = now

  try {
    const msg = Handshake.createMessageInitiation(peer.handshake, self.publicKey, self.privateKey)

    self.indexTable.set(peer.handshake.localIndex, { peer, handshake: peer.handshake })

    const cookieGen = self.cookieGenerators.get(peer.publicKeyHex)
    if (cookieGen) cookieGen.addMacs(msg)

    sendToEndpoint(self, peer, msg)
  } catch (err) {
    self.events.emit("error", err as Error)
  }
}

export function sendPacket(self: Device, peer: Peer.Peer, data: Uint8Array): void {
  if (Peer.needsRekey(peer)) {
    peer.stagedPackets.push(data)
    if (peer.stagedPackets.length > 128) peer.stagedPackets.shift()
    initiateHandshake(self, peer)
    return
  }

  const keypair = Peer.getSendKeypair(peer)
  if (!keypair) {
    peer.stagedPackets.push(data)
    if (peer.stagedPackets.length > 128) peer.stagedPackets.shift()
    initiateHandshake(self, peer)
    return
  }

  encryptAndSend(self, peer, keypair, data)
}

function encryptAndSend(
  self: Device,
  peer: Peer.Peer,
  keypair: Handshake.Keypair,
  plaintext: Uint8Array,
): void {
  const nonce = keypair.sendNonce++

  if (nonce >= Handshake.RejectAfterMessages) {
    initiateHandshake(self, peer)
    return
  }

  const paddedLen =
    plaintext.length > 0 ? (plaintext.length + PADDING_MULTIPLE - 1) & ~(PADDING_MULTIPLE - 1) : 0
  const padded = new Uint8Array(paddedLen)
  padded.set(plaintext)

  const nonceBytes = new Uint8Array(12)
  const nonceView = new DataView(nonceBytes.buffer)
  nonceView.setUint32(4, nonce >>> 0, true)
  nonceView.setUint32(8, (nonce / 0x100000000) >>> 0, true)

  const encrypted = ChaCha20Poly1305.seal(keypair.sendKey, nonceBytes, padded)

  const msg = new Uint8Array(Handshake.MessageTransportHeaderSize + encrypted.length)
  const view = new DataView(msg.buffer)
  view.setUint32(0, Handshake.MessageTransportType, true)
  view.setUint32(Handshake.MessageTransportOffsetReceiver, keypair.remoteIndex, true)
  view.setUint32(Handshake.MessageTransportOffsetCounter, nonce >>> 0, true)
  view.setUint32(Handshake.MessageTransportOffsetCounter + 4, (nonce / 0x100000000) >>> 0, true)
  msg.set(encrypted, Handshake.MessageTransportOffsetContent)

  sendToEndpoint(self, peer, msg)
  peer.lastSentPacket = Date.now()
}

function sendKeepalive(self: Device, peer: Peer.Peer): void {
  const keypair = Peer.getSendKeypair(peer)
  if (!keypair) return
  encryptAndSend(self, peer, keypair, new Uint8Array(0))
}

function flushStagedPackets(self: Device, peer: Peer.Peer): void {
  const packets = peer.stagedPackets
  peer.stagedPackets = []
  for (const pkt of packets) {
    sendPacket(self, peer, pkt)
  }
  Peer.startKeepalive(peer)
}

function handleIncoming(self: Device, buf: Buffer, rinfo: NDgram.RemoteInfo): void {
  const msg = new Uint8Array(buf)
  if (msg.length < 4) return

  const msgType = new DataView(msg.buffer, msg.byteOffset, msg.byteLength).getUint32(0, true)

  switch (msgType) {
    case Handshake.MessageInitiationType:
      handleInitiation(self, msg, rinfo)
      break
    case Handshake.MessageResponseType:
      handleResponse(self, msg, rinfo)
      break
    case Handshake.MessageCookieReplyType:
      handleCookieReply(self, msg, rinfo)
      break
    case Handshake.MessageTransportType:
      handleTransport(self, msg, rinfo)
      break
  }
}

function handleInitiation(self: Device, msg: Uint8Array, rinfo: NDgram.RemoteInfo): void {
  if (msg.length !== Handshake.MessageInitiationSize) return

  if (!self.cookieChecker.checkMAC1(msg)) return

  const result = Handshake.consumeMessageInitiation(msg, self.publicKey, self.privateKey, (pk) =>
    lookupPeerByPublicKey(self, pk),
  )

  if (!result) return

  const peer = result.peer
  const peerObj = findPeerByHandshake(self, peer)
  if (!peerObj) return

  peerObj.endpoint = `${rinfo.address}:${rinfo.port}`

  try {
    const response = Handshake.createMessageResponse(peer)

    self.indexTable.set(peer.localIndex, { peer: peerObj, handshake: peer })

    const cookieGen = self.cookieGenerators.get(peerObj.publicKeyHex)
    if (cookieGen) cookieGen.addMacs(response)

    sendToEndpoint(self, peerObj, response)

    Peer.activateKeypair(peerObj)

    if (peerObj.nextKeypair) {
      self.indexTable.set(peerObj.nextKeypair.localIndex, {
        peer: peerObj,
        keypair: peerObj.nextKeypair,
      })
    }
    if (peerObj.currentKeypair) {
      self.indexTable.set(peerObj.currentKeypair.localIndex, {
        peer: peerObj,
        keypair: peerObj.currentKeypair,
      })
    }
  } catch (err) {
    self.events.emit("error", err as Error)
  }
}

function handleResponse(self: Device, msg: Uint8Array, rinfo: NDgram.RemoteInfo): void {
  if (msg.length !== Handshake.MessageResponseSize) return

  if (!self.cookieChecker.checkMAC1(msg)) return

  const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength)
  const receiverIndex = view.getUint32(8, true)

  const entry = self.indexTable.get(receiverIndex)
  if (!entry?.peer) return

  const peer = entry.peer
  const ok = Handshake.consumeMessageResponse(msg, peer.handshake, self.privateKey)
  if (!ok) return

  peer.endpoint = `${rinfo.address}:${rinfo.port}`

  Peer.activateKeypair(peer)

  if (peer.currentKeypair) {
    self.indexTable.set(peer.currentKeypair.localIndex, { peer, keypair: peer.currentKeypair })
  }
  if (peer.previousKeypair) {
    self.indexTable.set(peer.previousKeypair.localIndex, { peer, keypair: peer.previousKeypair })
  }

  sendKeepalive(self, peer)
}

function handleCookieReply(self: Device, msg: Uint8Array, _rinfo: NDgram.RemoteInfo): void {
  if (msg.length !== Handshake.MessageCookieReplySize) return

  const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength)
  const receiverIndex = view.getUint32(4, true)

  const entry = self.indexTable.get(receiverIndex)
  if (!entry?.peer) return

  const cookieGen = self.cookieGenerators.get(entry.peer.publicKeyHex)
  if (cookieGen) cookieGen.consumeReply(msg)
}

function handleTransport(self: Device, msg: Uint8Array, rinfo: NDgram.RemoteInfo): void {
  if (msg.length < Handshake.MessageTransportHeaderSize + 16) return

  const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength)
  const receiverIndex = view.getUint32(Handshake.MessageTransportOffsetReceiver, true)
  const counterLow = view.getUint32(Handshake.MessageTransportOffsetCounter, true)
  const counterHigh = view.getUint32(Handshake.MessageTransportOffsetCounter + 4, true)
  const counter = counterLow + counterHigh * 0x100000000

  const entry = self.indexTable.get(receiverIndex)
  if (!entry?.peer) return

  const peer = entry.peer
  const keypair = entry.keypair ?? Peer.findKeypairByIndex(peer, receiverIndex)
  if (!keypair) return

  if (Date.now() - keypair.created > Handshake.RejectAfterTime) return

  if (!keypair.replayFilter.validateCounter(counter, Handshake.RejectAfterMessages)) return

  const nonceBytes = new Uint8Array(12)
  const nonceView = new DataView(nonceBytes.buffer)
  nonceView.setUint32(4, counterLow, true)
  nonceView.setUint32(8, counterHigh, true)

  const ciphertext = msg.subarray(Handshake.MessageTransportOffsetContent)
  const plaintext = ChaCha20Poly1305.open(keypair.receiveKey, nonceBytes, ciphertext)
  if (!plaintext) return

  peer.endpoint = `${rinfo.address}:${rinfo.port}`
  peer.lastReceivedPacket = Date.now()

  if (peer.nextKeypair === keypair) {
    Peer.receivedWithKeypair(peer, keypair)
  }

  if (plaintext.length > 0) {
    let end = plaintext.length
    if (plaintext.length >= 4) {
      const version = (plaintext[0]! >> 4) & 0xf
      if (version === 4) {
        const totalLen = (plaintext[2]! << 8) | plaintext[3]!
        if (totalLen > 0 && totalLen <= plaintext.length) {
          end = totalLen
        }
      } else if (version === 6 && plaintext.length >= 40) {
        const payloadLen = (plaintext[4]! << 8) | plaintext[5]!
        const totalLen = 40 + payloadLen
        if (totalLen > 0 && totalLen <= plaintext.length) {
          end = totalLen
        }
      }
    }
    self.events.emit("packet", plaintext.subarray(0, end), peer)
  }
}

function sendToEndpoint(self: Device, peer: Peer.Peer, data: Uint8Array): void {
  if (!peer.endpoint || !self.socket) return

  const [host, portStr] = peer.endpoint.split(":")
  const port = parseInt(portStr!, 10)
  if (!host || isNaN(port)) return

  self.socket.send(Buffer.from(data), port, host, (err) => {
    if (err) self.events.emit("error", err)
  })
}

function lookupPeerByPublicKey(self: Device, pk: Uint8Array): Handshake.HandshakeContext | null {
  const hex = Buffer.from(pk).toString("hex")
  const peer = self.peers.get(hex)
  return peer?.handshake ?? null
}

function findPeerByHandshake(self: Device, hs: Handshake.HandshakeContext): Peer.Peer | null {
  for (const peer of self.peers.values()) {
    if (peer.handshake === hs) return peer
  }
  return null
}
