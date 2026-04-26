/**
 * Minimal IPv4 UDP session layer for outbound datagrams over WireGuard.
 */
import * as NEvents from "node:events"
import type * as Peer from "../wireguard/Peer.ts"
import type * as TypedEmitter from "../util/TypedEmitter.ts"
import * as IPv4 from "./IPv4.ts"

export { IPv4 }

export interface PacketTransport {
  events: TypedEmitter.TypedEmitter<{ packet: [data: Uint8Array, peer: Peer.Peer] }>
  sendPacket(peer: Peer.Peer, data: Uint8Array): void
}

const UdpHeaderLen = 8

export const IpProtocol = {
  Udp: 17,
} as const

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

function udpChecksum(srcIp: Uint8Array, dstIp: Uint8Array, segment: Uint8Array): number {
  const pseudoLen = 12 + segment.length
  const pseudo = new Uint8Array(pseudoLen + (pseudoLen & 1))
  pseudo.set(srcIp, 0)
  pseudo.set(dstIp, 4)
  pseudo[8] = 0
  pseudo[9] = IpProtocol.Udp
  new DataView(pseudo.buffer).setUint16(10, segment.length, false)
  pseudo.set(segment, 12)

  const sum = IPv4.checksum(pseudo)
  return sum === 0 ? 0xffff : sum
}

export function buildUdpSegment(
  srcPort: number,
  dstPort: number,
  payload: Uint8Array,
  srcIp: Uint8Array,
  dstIp: Uint8Array,
): Uint8Array {
  if (srcPort < 0 || srcPort > 0xffff || dstPort < 0 || dstPort > 0xffff) {
    throw new Error("UDP port out of range")
  }

  const segment = new Uint8Array(UdpHeaderLen + payload.length)
  const view = new DataView(segment.buffer)
  view.setUint16(0, srcPort, false)
  view.setUint16(2, dstPort, false)
  view.setUint16(4, segment.length, false)
  view.setUint16(6, 0, false)
  segment.set(payload, UdpHeaderLen)
  view.setUint16(6, udpChecksum(srcIp, dstIp, segment), false)
  return segment
}

export interface UdpSegment {
  srcPort: number
  dstPort: number
  length: number
  checksum: number
  payload: Uint8Array
}

export function parseUdpSegment(data: Uint8Array): UdpSegment | null {
  if (data.length < UdpHeaderLen) return null
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  const length = view.getUint16(4, false)
  if (length < UdpHeaderLen || length > data.length) return null

  return {
    srcPort: view.getUint16(0, false),
    dstPort: view.getUint16(2, false),
    length,
    checksum: view.getUint16(6, false),
    payload: data.subarray(UdpHeaderLen, length),
  }
}

function connectionKey(localPort: number, remotePort: number, remoteIp: Uint8Array): string {
  return `${localPort}:${IPv4.format(remoteIp)}:${remotePort}`
}

let nextEphemeralPort = 49152 + Math.floor(Math.random() * 8192)

function allocatePort(): number {
  const port = nextEphemeralPort++
  if (nextEphemeralPort > 65535) nextEphemeralPort = 49152
  return port
}

export class UdpSession extends NEvents.EventEmitter {
  #localIp: Uint8Array
  #remoteIp: Uint8Array
  #localPort: number
  #remotePort: number
  #peer: Peer.Peer
  #device: PacketTransport
  #ipId = 1
  #closed = false
  #onClose: (() => void) | null = null

  constructor(
    localIp: Uint8Array,
    remoteIp: Uint8Array,
    localPort: number,
    remotePort: number,
    peer: Peer.Peer,
    device: PacketTransport,
  ) {
    super()
    this.#localIp = localIp
    this.#remoteIp = remoteIp
    this.#localPort = localPort
    this.#remotePort = remotePort
    this.#peer = peer
    this.#device = device
  }

  get localPort(): number {
    return this.#localPort
  }

  get remotePort(): number {
    return this.#remotePort
  }

  get remoteAddress(): string {
    return IPv4.format(this.#remoteIp)
  }

  get closed(): boolean {
    return this.#closed
  }

  send(payload: Uint8Array): void {
    if (this.#closed) return

    const segment = buildUdpSegment(
      this.#localPort,
      this.#remotePort,
      payload,
      this.#localIp,
      this.#remoteIp,
    )
    const packet = IPv4.buildPacket(
      this.#localIp,
      this.#remoteIp,
      IpProtocol.Udp,
      segment,
      this.#ipId++,
    )
    if (this.#ipId > 0xffff) this.#ipId = 1
    this.#device.sendPacket(this.#peer, packet)
  }

  handlePacket(segment: UdpSegment): void {
    if (this.#closed) return
    this.emit("message", new Uint8Array(segment.payload))
  }

  onClosed(cb: () => void): void {
    this.#onClose = cb
  }

  close(): void {
    if (this.#closed) return
    this.#closed = true
    this.#onClose?.()
    this.removeAllListeners()
  }

  get key(): string {
    return connectionKey(this.#localPort, this.#remotePort, this.#remoteIp)
  }
}

export class UdpStack {
  #device: PacketTransport
  #localIp: Uint8Array
  #sessions: Map<string, UdpSession> = new Map()
  #packetHandler: (data: Uint8Array, peer: Peer.Peer) => void

  constructor(device: PacketTransport, localIp: string) {
    this.#device = device
    this.#localIp = IPv4.parse(localIp)
    this.#packetHandler = (data: Uint8Array, _peer: Peer.Peer) => this.#handleIpPacket(data)
    this.#device.events.on("packet", this.#packetHandler)
  }

  connect(host: string, port: number, peer: Peer.Peer): UdpSession {
    const remoteIp = IPv4.parse(host)
    const localPort = allocatePort()
    const session = new UdpSession(this.#localIp, remoteIp, localPort, port, peer, this.#device)

    this.#sessions.set(session.key, session)
    session.onClosed(() => {
      this.#sessions.delete(session.key)
    })
    return session
  }

  #handleIpPacket(packet: Uint8Array): void {
    const ip = IPv4.parsePacket(packet)
    if (!ip) return
    if (ip.protocol !== IpProtocol.Udp) return
    if (!bytesEqual(ip.dst, this.#localIp)) return

    const udp = parseUdpSegment(ip.payload)
    if (!udp) return

    const key = connectionKey(udp.dstPort, udp.srcPort, ip.src)
    const session = this.#sessions.get(key)
    if (!session) return

    session.handlePacket(udp)
  }

  destroy(): void {
    this.#device.events.off("packet", this.#packetHandler)
    for (const session of this.#sessions.values()) {
      session.close()
    }
    this.#sessions.clear()
  }
}
