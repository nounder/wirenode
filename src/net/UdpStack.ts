/**
 * Minimal IPv4 UDP session layer for outbound datagrams over WireGuard.
 */
import * as NEvents from "node:events"
import type { Device } from "../wireguard/Device.ts"
import type { Peer } from "../wireguard/Peer.ts"

const IpVersion = 4
const Ipv4HeaderLen = 20
const IpTtl = 64
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

export function ipChecksum(data: Uint8Array): number {
  let sum = 0
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  for (let i = 0; i < data.length - 1; i += 2) {
    sum += view.getUint16(i, false)
  }
  if (data.length & 1) {
    sum += data[data.length - 1]! << 8
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16)
  }
  return (~sum) & 0xffff
}

function parseIpv4Address(address: string): Uint8Array {
  const parts = address.split(".")
  if (parts.length !== 4) throw new Error(`invalid IPv4 address: ${address}`)

  const parsed = new Uint8Array(4)
  for (let i = 0; i < 4; i++) {
    const part = Number(parts[i])
    if (!Number.isInteger(part) || part < 0 || part > 255) {
      throw new Error(`invalid IPv4 address: ${address}`)
    }
    parsed[i] = part
  }
  return parsed
}

function formatIpv4Address(address: Uint8Array): string {
  return `${address[0]}.${address[1]}.${address[2]}.${address[3]}`
}

function buildIpv4Packet(
  src: Uint8Array,
  dst: Uint8Array,
  protocol: number,
  payload: Uint8Array,
  id: number,
): Uint8Array {
  const totalLength = Ipv4HeaderLen + payload.length
  const packet = new Uint8Array(totalLength)
  const view = new DataView(packet.buffer)

  packet[0] = (IpVersion << 4) | (Ipv4HeaderLen >> 2)
  packet[1] = 0
  view.setUint16(2, totalLength, false)
  view.setUint16(4, id & 0xffff, false)
  view.setUint16(6, 0x4000, false)
  packet[8] = IpTtl
  packet[9] = protocol
  packet.set(src, 12)
  packet.set(dst, 16)

  view.setUint16(10, 0, false)
  view.setUint16(10, ipChecksum(packet.subarray(0, Ipv4HeaderLen)), false)
  packet.set(payload, Ipv4HeaderLen)
  return packet
}

export interface Ipv4Packet {
  src: Uint8Array
  dst: Uint8Array
  protocol: number
  payload: Uint8Array
  totalLength: number
}

function parseIpv4Packet(packet: Uint8Array): Ipv4Packet | null {
  if (packet.length < Ipv4HeaderLen) return null
  const version = (packet[0]! >> 4) & 0xf
  if (version !== 4) return null

  const ihl = (packet[0]! & 0xf) * 4
  if (ihl < Ipv4HeaderLen || packet.length < ihl) return null

  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength)
  const totalLength = view.getUint16(2, false)
  if (totalLength < ihl || totalLength > packet.length) return null

  return {
    src: new Uint8Array(packet.subarray(12, 16)),
    dst: new Uint8Array(packet.subarray(16, 20)),
    protocol: packet[9]!,
    payload: packet.subarray(ihl, totalLength),
    totalLength,
  }
}

export const IPv4 = {
  parse: parseIpv4Address,
  format: formatIpv4Address,
  buildPacket: buildIpv4Packet,
  parsePacket: parseIpv4Packet,
} as const

function udpChecksum(srcIp: Uint8Array, dstIp: Uint8Array, segment: Uint8Array): number {
  const pseudoLen = 12 + segment.length
  const pseudo = new Uint8Array(pseudoLen + (pseudoLen & 1))
  pseudo.set(srcIp, 0)
  pseudo.set(dstIp, 4)
  pseudo[8] = 0
  pseudo[9] = IpProtocol.Udp
  new DataView(pseudo.buffer).setUint16(10, segment.length, false)
  pseudo.set(segment, 12)

  const checksum = ipChecksum(pseudo)
  return checksum === 0 ? 0xffff : checksum
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
  #peer: Peer
  #device: Device
  #ipId = 1
  #closed = false
  #onClose: (() => void) | null = null

  constructor(
    localIp: Uint8Array,
    remoteIp: Uint8Array,
    localPort: number,
    remotePort: number,
    peer: Peer,
    device: Device,
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
  #device: Device
  #localIp: Uint8Array
  #sessions: Map<string, UdpSession> = new Map()
  #packetHandler: (data: Uint8Array, peer: Peer) => void

  constructor(device: Device, localIp: string) {
    this.#device = device
    this.#localIp = IPv4.parse(localIp)
    this.#packetHandler = (data: Uint8Array, _peer: Peer) => this.#handleIpPacket(data)
    this.#device.on("packet", this.#packetHandler)
  }

  connect(host: string, port: number, peer: Peer): UdpSession {
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
    this.#device.off("packet", this.#packetHandler)
    for (const session of this.#sessions.values()) {
      session.close()
    }
    this.#sessions.clear()
  }
}
