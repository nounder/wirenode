/**
 * Integration test: send a DNS query through the UDP proxy over WireGuard.
 *
 * Usage:
 *   bun run test-mullvad-udp.ts <config-file> [dns-server] [domain]
 */

import * as NDgram from "node:dgram"
import { parseConfig } from "./src/wireguard/Config.ts"
import { Device } from "./src/wireguard/Device.ts"
import { VirtualTun } from "./src/net/VirtualTun.ts"
import { startUdpProxy } from "./src/proxy/UdpProxy.ts"

const configPath = process.argv[2]
if (!configPath) {
  console.error("Usage: bun run test-mullvad-udp.ts <config-file> [dns-server] [domain]")
  process.exit(1)
}

const configText = await Bun.file(configPath).text()
const conf = parseConfig(configText)
const dnsServer = process.argv[3] ?? conf.interface.dns[0] ?? "1.1.1.1"
const domain = process.argv[4] ?? "example.com"

function buildDnsQuery(name: string): { id: number; packet: Uint8Array } {
  const labels = name.split(".").filter(Boolean)
  const qnameLen = labels.reduce((sum, label) => sum + 1 + label.length, 1)
  const packet = new Uint8Array(12 + qnameLen + 4)
  const view = new DataView(packet.buffer)
  const id = Math.floor(Math.random() * 0x10000)

  view.setUint16(0, id, false)
  view.setUint16(2, 0x0100, false) // recursion desired
  view.setUint16(4, 1, false) // QDCOUNT
  view.setUint16(6, 0, false) // ANCOUNT
  view.setUint16(8, 0, false) // NSCOUNT
  view.setUint16(10, 0, false) // ARCOUNT

  let offset = 12
  for (const label of labels) {
    if (label.length > 63) throw new Error(`DNS label too long: ${label}`)
    packet[offset++] = label.length
    packet.set(new TextEncoder().encode(label), offset)
    offset += label.length
  }
  packet[offset++] = 0
  view.setUint16(offset, 1, false) // A
  view.setUint16(offset + 2, 1, false) // IN

  return { id, packet }
}

function skipDnsName(packet: Uint8Array, offset: number): number {
  while (offset < packet.length) {
    const len = packet[offset]!
    if ((len & 0xc0) === 0xc0) return offset + 2
    if (len === 0) return offset + 1
    offset += 1 + len
  }
  throw new Error("malformed DNS name")
}

function parseDnsARecords(packet: Uint8Array, expectedId: number): string[] {
  if (packet.length < 12) throw new Error("short DNS response")
  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength)
  const id = view.getUint16(0, false)
  if (id !== expectedId) throw new Error(`unexpected DNS response id: ${id}`)

  const flags = view.getUint16(2, false)
  const rcode = flags & 0x000f
  if (rcode !== 0) throw new Error(`DNS response returned rcode ${rcode}`)

  const qdCount = view.getUint16(4, false)
  const anCount = view.getUint16(6, false)
  let offset = 12

  for (let i = 0; i < qdCount; i++) {
    offset = skipDnsName(packet, offset) + 4
  }

  const records: string[] = []
  for (let i = 0; i < anCount; i++) {
    offset = skipDnsName(packet, offset)
    if (offset + 10 > packet.length) throw new Error("truncated DNS answer")

    const type = view.getUint16(offset, false)
    const klass = view.getUint16(offset + 2, false)
    const rdLength = view.getUint16(offset + 8, false)
    offset += 10
    if (offset + rdLength > packet.length) throw new Error("truncated DNS rdata")

    if (type === 1 && klass === 1 && rdLength === 4) {
      records.push(
        `${packet[offset]}.${packet[offset + 1]}.${packet[offset + 2]}.${packet[offset + 3]}`,
      )
    }
    offset += rdLength
  }

  return records
}

function waitForUdpMessage(socket: NDgram.Socket, timeoutMs: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      cleanup()
      reject(new Error(`timed out after ${timeoutMs}ms waiting for UDP response`))
    }, timeoutMs)

    const cleanup = () => {
      clearTimeout(timeout)
      socket.off("message", onMessage)
      socket.off("error", onError)
    }
    const onMessage = (msg: Buffer) => {
      cleanup()
      resolve(msg)
    }
    const onError = (err: Error) => {
      cleanup()
      reject(err)
    }

    socket.once("message", onMessage)
    socket.once("error", onError)
  })
}

const device = new Device({
  privateKey: conf.interface.privateKey,
  listenPort: conf.interface.listenPort,
  peers: conf.peers,
  mtu: conf.interface.mtu,
})

await device.up()
console.log(`WireGuard device up on port ${device.getPort()}`)

device.on("error", (err: Error) => {
  console.error(`WireGuard error: ${err.message}`)
})

const vt = new VirtualTun({
  device,
  addresses: conf.interface.address,
  dns: conf.interface.dns,
  resolveConfig: conf.resolve,
})

const peer = device.getPeers()[0]
if (!peer) throw new Error("configuration has no peers")

console.log(`Initiating handshake with ${peer.endpoint}...`)
await new Promise<void>((resolve, reject) => {
  const timeout = setTimeout(() => reject(new Error("handshake timed out after 10s")), 10_000)
  device.once("handshakeComplete", () => {
    clearTimeout(timeout)
    resolve()
  })
  device.initiateHandshake(peer)
})
console.log("Handshake complete")

const proxyBind = "127.0.0.1:18200"
await startUdpProxy({
  bindAddress: proxyBind,
  target: `${dnsServer}:53`,
  inactivityTimeout: 15,
  dial: (target) => vt.dialUdp(target),
})
console.log(`UDP proxy ready on ${proxyBind}, forwarding DNS to ${dnsServer}:53`)

const client = NDgram.createSocket("udp4")
const { id, packet } = buildDnsQuery(domain)

try {
  const responsePromise = waitForUdpMessage(client, 10_000)
  client.send(packet, 18200, "127.0.0.1")
  const response = await responsePromise
  const records = parseDnsARecords(new Uint8Array(response), id)

  console.log(`DNS response for ${domain}: ${records.join(", ") || "(no A records)"}`)
  if (records.length === 0) {
    process.exitCode = 1
  }
} finally {
  client.close()
  vt.destroy()
  await device.down()
}

process.exit(process.exitCode ?? 0)
