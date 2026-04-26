import { test, expect } from "bun:test"
import * as NEvents from "node:events"
import type { Device } from "../wireguard/Device.ts"
import type { Peer } from "../wireguard/Peer.ts"
import {
  buildUdpSegment,
  IpProtocol,
  IPv4,
  parseUdpSegment,
  UdpStack,
} from "./UdpStack.ts"

class FakeDevice extends NEvents.EventEmitter {
  sent: Array<{ peer: Peer; packet: Uint8Array }> = []

  sendPacket(peer: Peer, packet: Uint8Array): void {
    this.sent.push({ peer, packet })
  }
}

function fakeDevice(): Device & FakeDevice {
  return new FakeDevice() as Device & FakeDevice
}

function fakePeer(): Peer {
  return {} as Peer
}

test("UdpSession sends IPv4 UDP packets through the WireGuard device", () => {
  const device = fakeDevice()
  const peer = fakePeer()
  const stack = new UdpStack(device, "10.0.0.2")
  const session = stack.connect("8.8.8.8", 53, peer)

  session.send(new TextEncoder().encode("query"))

  expect(device.sent.length).toBe(1)
  expect(device.sent[0]!.peer).toBe(peer)

  const ip = IPv4.parsePacket(device.sent[0]!.packet)
  expect(ip).not.toBeNull()
  expect(ip!.protocol).toBe(IpProtocol.Udp)
  expect(Array.from(ip!.src)).toEqual([10, 0, 0, 2])
  expect(Array.from(ip!.dst)).toEqual([8, 8, 8, 8])

  const udp = parseUdpSegment(ip!.payload)
  expect(udp).not.toBeNull()
  expect(udp!.srcPort).toBe(session.localPort)
  expect(udp!.dstPort).toBe(53)
  expect(udp!.checksum).not.toBe(0)
  expect(new TextDecoder().decode(udp!.payload)).toBe("query")

  stack.destroy()
})

test("UdpStack demuxes inbound UDP replies to the matching session", async () => {
  const device = fakeDevice()
  const peer = fakePeer()
  const stack = new UdpStack(device, "10.0.0.2")
  const session = stack.connect("8.8.8.8", 53, peer)

  const received = new Promise<Uint8Array>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("timed out waiting for UDP reply")), 1000)
    session.once("message", (msg: Uint8Array) => {
      clearTimeout(timeout)
      resolve(msg)
    })
  })

  const srcIp = IPv4.parse("8.8.8.8")
  const dstIp = IPv4.parse("10.0.0.2")
  const segment = buildUdpSegment(
    53,
    session.localPort,
    new TextEncoder().encode("response"),
    srcIp,
    dstIp,
  )
  const packet = IPv4.buildPacket(srcIp, dstIp, IpProtocol.Udp, segment, 7)

  device.emit("packet", packet, peer)

  expect(new TextDecoder().decode(await received)).toBe("response")
  stack.destroy()
})

test("UdpStack drops inbound UDP packets without a matching session", () => {
  const device = fakeDevice()
  const peer = fakePeer()
  const stack = new UdpStack(device, "10.0.0.2")
  const session = stack.connect("8.8.8.8", 53, peer)
  let received = false
  session.on("message", () => {
    received = true
  })

  const srcIp = IPv4.parse("1.1.1.1")
  const dstIp = IPv4.parse("10.0.0.2")
  const segment = buildUdpSegment(53, session.localPort, new Uint8Array([1, 2, 3]), srcIp, dstIp)
  const packet = IPv4.buildPacket(srcIp, dstIp, IpProtocol.Udp, segment, 9)

  device.emit("packet", packet, peer)

  expect(received).toBe(false)
  stack.destroy()
})
