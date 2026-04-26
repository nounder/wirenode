export const HeaderLen = 20
const Version = 4
const Ttl = 64

export function parse(address: string): Uint8Array {
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

export function format(address: Uint8Array): string {
  return `${address[0]}.${address[1]}.${address[2]}.${address[3]}`
}

export function toNumber(address: string): number | null {
  const parts = address.split(".")
  if (parts.length !== 4) return null
  let n = 0
  for (const p of parts) {
    const part = Number(p)
    if (!Number.isInteger(part) || part < 0 || part > 255) return null
    n = (n << 8) | part
  }
  return n >>> 0
}

export function checksum(packet: Uint8Array): number {
  let sum = 0
  for (let i = 0; i < packet.length - 1; i += 2) {
    sum += (packet[i]! << 8) | packet[i + 1]!
  }
  if (packet.length & 1) sum += packet[packet.length - 1]! << 8
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16)
  }
  return (~sum) & 0xffff
}

export function buildPacket(
  src: Uint8Array,
  dst: Uint8Array,
  protocol: number,
  payload: Uint8Array,
  id: number,
): Uint8Array {
  const totalLength = HeaderLen + payload.length
  const packet = new Uint8Array(totalLength)
  const view = new DataView(packet.buffer)

  packet[0] = (Version << 4) | (HeaderLen >> 2)
  packet[1] = 0
  view.setUint16(2, totalLength, false)
  view.setUint16(4, id & 0xffff, false)
  view.setUint16(6, 0x4000, false)
  packet[8] = Ttl
  packet[9] = protocol
  packet.set(src, 12)
  packet.set(dst, 16)

  view.setUint16(10, 0, false)
  view.setUint16(10, checksum(packet.subarray(0, HeaderLen)), false)
  packet.set(payload, HeaderLen)
  return packet
}

export interface Packet {
  src: Uint8Array
  dst: Uint8Array
  protocol: number
  payload: Uint8Array
  totalLength: number
}

export function parsePacket(packet: Uint8Array): Packet | null {
  if (packet.length < HeaderLen) return null
  const version = (packet[0]! >> 4) & 0xf
  if (version !== 4) return null

  const ihl = (packet[0]! & 0xf) * 4
  if (ihl < HeaderLen || packet.length < ihl) return null

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
