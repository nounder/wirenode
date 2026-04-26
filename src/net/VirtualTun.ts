import * as NDns from "node:dns"
import * as Device from "../wireguard/Device.ts"
import * as Peer from "../wireguard/Peer.ts"
import { TcpStack, TcpConnection } from "./TcpStack.ts"
import { UdpStack, type UdpSession } from "./UdpStack.ts"
import * as Config from "../wireguard/Config.ts"
import * as Address from "./Address.ts"
import * as IPv4 from "./IPv4.ts"

export interface OpenOptions {
  device: Device.Device
  addresses: string[]
  dns: string[]
  resolveConfig: Config.ResolveConfig
}

export interface VirtualTun {
  readonly device: Device.Device
  readonly addresses: string[]
  readonly dns: string[]
  resolveStrategy: Config.ResolveConfig["resolveStrategy"]
}

export type VirtualTunResource = VirtualTun & {
  tcpStack: TcpStack | null
  udpStack: UdpStack | null
} & AsyncDisposable

export function open(options: OpenOptions): VirtualTunResource {
  let resolveStrategy = options.resolveConfig.resolveStrategy

  if (resolveStrategy === "auto") {
    const hasV4 = options.addresses.some((a) => !a.includes(":"))
    resolveStrategy = hasV4 ? "ipv4" : "ipv6"
  }

  const self: VirtualTun = {
    device: options.device,
    addresses: options.addresses,
    dns: options.dns,
    resolveStrategy,
  }

  const ipv4Addr = self.addresses.find((a) => !a.includes(":"))
  const transport = ipv4Addr ? Device.asTransport(self.device) : null
  const tcpStack = ipv4Addr && transport ? new TcpStack(transport, ipv4Addr) : null
  const udpStack = ipv4Addr && transport ? new UdpStack(transport, ipv4Addr) : null

  return Object.create(self, {
    tcpStack: { value: tcpStack, writable: true },
    udpStack: { value: udpStack, writable: true },
    [Symbol.asyncDispose]: {
      value: async () => {
        tcpStack?.destroy()
        udpStack?.destroy()
      },
    },
  }) as VirtualTunResource
}

export function close(self: VirtualTunResource): void {
  self.tcpStack?.destroy()
  self.udpStack?.destroy()
}

export async function resolve(self: VirtualTun, hostname: string): Promise<string> {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) return hostname
  if (hostname.includes(":")) return hostname

  return new Promise((res, reject) => {
    const family = self.resolveStrategy === "ipv4" ? 4 : 6
    NDns.lookup(hostname, { family, all: false }, (err, address) => {
      if (err) {
        NDns.lookup(hostname, (err2, addr2) => {
          if (err2) reject(err2)
          else res(addr2)
        })
      } else {
        res(address)
      }
    })
  })
}

export async function dial(self: VirtualTunResource, host: string, port: number): Promise<TcpConnection> {
  const resolved = await resolve(self, host)
  const peer = findPeerForAddress(self, resolved)

  if (!peer?.endpoint) {
    throw new Error(`no peer found for ${host}:${port}`)
  }

  if (!peer.currentKeypair) {
    await ensureHandshake(self, peer)
  }

  if (!self.tcpStack) {
    throw new Error("no IPv4 address configured — TCP stack unavailable")
  }

  const conn = self.tcpStack.connect(resolved, port, peer)

  const timeout = new Promise<never>((_, reject) =>
    setTimeout(() => {
      conn.close()
      reject(new Error("TCP connect timeout"))
    }, 15_000),
  )

  await Promise.race([conn.connected(), timeout])
  return conn
}

export async function dialUdp(self: VirtualTunResource, target: string): Promise<UdpSession> {
  const addr = Address.parse(target)
  const resolved = await resolve(self, addr.host)
  if (resolved.includes(":")) {
    throw new Error("UDP over WireGuard currently supports IPv4 targets only")
  }

  const peer = findPeerForAddress(self, resolved)
  if (!peer?.endpoint) {
    throw new Error(`no peer found for UDP target ${target}`)
  }

  if (!peer.currentKeypair) {
    await ensureHandshake(self, peer)
  }

  if (!self.udpStack) {
    throw new Error("no IPv4 address configured — UDP stack unavailable")
  }

  return self.udpStack.connect(resolved, addr.port, peer)
}

function ensureHandshake(self: VirtualTun, peer: Peer.Peer): Promise<void> {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      peer.events.off("keypairReady", onReady)
      reject(new Error("handshake timeout"))
    }, 10_000)

    const onReady = () => {
      clearTimeout(timeout)
      resolve()
    }

    peer.events.once("keypairReady", onReady)
    Device.initiateHandshake(self.device, peer)
  })
}

function findPeerForAddress(self: VirtualTun, addr: string): Peer.Peer | null {
  const peers = Device.getPeers(self.device)

  for (const peer of peers) {
    for (const cidr of peer.allowedIPs) {
      if (cidr === "0.0.0.0/0" || cidr === "::/0") return peer
      if (ipInCIDR(addr, cidr)) return peer
    }
  }

  return peers[0] ?? null
}

function ipInCIDR(ip: string, cidr: string): boolean {
  const [prefix, bitsStr] = cidr.split("/")
  if (!prefix || !bitsStr) return ip === cidr

  const bits = parseInt(bitsStr, 10)
  const ipNum = IPv4.toNumber(ip)
  const prefixNum = IPv4.toNumber(prefix)
  if (ipNum === null || prefixNum === null) return false

  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
  return (ipNum & mask) === (prefixNum & mask)
}
