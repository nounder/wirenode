import * as NDns from "node:dns"
import { Device } from "../wireguard/Device.ts"
import { Peer } from "../wireguard/Peer.ts"
import { TcpStack, TcpConnection } from "./TcpStack.ts"
import { UdpStack, type UdpSession } from "./UdpStack.ts"
import type { ResolveConfig } from "../wireguard/Config.ts"

export interface VirtualTunOptions {
  device: Device
  addresses: string[] // local interface addresses
  dns: string[]
  resolveConfig: ResolveConfig
}

export class VirtualTun {
  readonly device: Device
  readonly addresses: string[]
  readonly dns: string[]
  #resolveStrategy: ResolveConfig["resolveStrategy"]
  #tcpStack: TcpStack | null = null
  #udpStack: UdpStack | null = null

  constructor(options: VirtualTunOptions) {
    this.device = options.device
    this.addresses = options.addresses
    this.dns = options.dns
    this.#resolveStrategy = options.resolveConfig.resolveStrategy

    // Auto-detect resolve strategy — prefer IPv4 since our TCP stack only supports IPv4
    if (this.#resolveStrategy === "auto") {
      const hasV4 = this.addresses.some((a) => !a.includes(":"))
      this.#resolveStrategy = hasV4 ? "ipv4" : "ipv6"
    }

    // Initialize userspace TCP/IP stack with our tunnel IP
    const ipv4Addr = this.addresses.find((a) => !a.includes(":"))
    if (ipv4Addr) {
      this.#tcpStack = new TcpStack(this.device, ipv4Addr)
      this.#udpStack = new UdpStack(this.device, ipv4Addr)
    }
  }

  async resolve(hostname: string): Promise<string> {
    // If it's already an IP, return as-is
    if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) return hostname
    if (hostname.includes(":")) return hostname

    return new Promise((resolve, reject) => {
      const family = this.#resolveStrategy === "ipv4" ? 4 : 6
      NDns.lookup(hostname, { family, all: false }, (err, address) => {
        if (err) {
          // Fallback to any
          NDns.lookup(hostname, (err2, addr2) => {
            if (err2) reject(err2)
            else resolve(addr2)
          })
        } else {
          resolve(address)
        }
      })
    })
  }

  async dial(host: string, port: number): Promise<TcpConnection> {
    const resolved = await this.resolve(host)
    const peer = this.#findPeerForAddress(resolved)

    if (!peer?.endpoint) {
      throw new Error(`no peer found for ${host}:${port}`)
    }

    // Ensure handshake is done
    if (!peer.currentKeypair) {
      await this.#ensureHandshake(peer)
    }

    if (!this.#tcpStack) {
      throw new Error("no IPv4 address configured — TCP stack unavailable")
    }

    // Connect through the userspace TCP/IP stack over the WireGuard tunnel
    const conn = this.#tcpStack.connect(resolved, port, peer)

    // Wait for TCP handshake with timeout
    const timeout = new Promise<never>((_, reject) =>
      setTimeout(() => {
        conn.close()
        reject(new Error("TCP connect timeout"))
      }, 15_000),
    )

    await Promise.race([conn.connected(), timeout])
    return conn
  }

  async dialUdp(target: string): Promise<UdpSession> {
    const { host, port } = parseHostPort(target)
    const resolved = await this.resolve(host)
    if (resolved.includes(":")) {
      throw new Error("UDP over WireGuard currently supports IPv4 targets only")
    }

    const peer = this.#findPeerForAddress(resolved)
    if (!peer?.endpoint) {
      throw new Error(`no peer found for UDP target ${target}`)
    }

    if (!peer.currentKeypair) {
      await this.#ensureHandshake(peer)
    }

    if (!this.#udpStack) {
      throw new Error("no IPv4 address configured — UDP stack unavailable")
    }

    return this.#udpStack.connect(resolved, port, peer)
  }

  #ensureHandshake(peer: Peer): Promise<void> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        peer.removeListener("keypairReady", onReady)
        reject(new Error("handshake timeout"))
      }, 10_000)

      const onReady = () => {
        clearTimeout(timeout)
        resolve()
      }

      peer.once("keypairReady", onReady)
      this.device.initiateHandshake(peer)
    })
  }

  #findPeerForAddress(addr: string): Peer | null {
    const peers = this.device.getPeers()

    for (const peer of peers) {
      for (const cidr of peer.allowedIPs) {
        if (cidr === "0.0.0.0/0" || cidr === "::/0") return peer
        if (this.#ipInCIDR(addr, cidr)) return peer
      }
    }

    // Fallback to first peer
    return peers[0] ?? null
  }

  #ipInCIDR(ip: string, cidr: string): boolean {
    const [prefix, bitsStr] = cidr.split("/")
    if (!prefix || !bitsStr) return ip === cidr

    const bits = parseInt(bitsStr, 10)
    const ipNum = this.#ipToNumber(ip)
    const prefixNum = this.#ipToNumber(prefix)
    if (ipNum === null || prefixNum === null) return false

    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0
    return (ipNum & mask) === (prefixNum & mask)
  }

  #ipToNumber(ip: string): number | null {
    const parts = ip.split(".")
    if (parts.length !== 4) return null
    return parts.reduce((acc, p) => (acc << 8) | parseInt(p, 10), 0) >>> 0
  }

  destroy(): void {
    this.#tcpStack?.destroy()
    this.#udpStack?.destroy()
  }
}

function parseHostPort(addr: string): { host: string; port: number } {
  const idx = addr.lastIndexOf(":")
  if (idx <= 0 || idx === addr.length - 1) {
    throw new Error(`invalid host:port address: ${addr}`)
  }

  const port = parseInt(addr.slice(idx + 1), 10)
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`invalid port in address: ${addr}`)
  }

  return {
    host: addr.slice(0, idx),
    port,
  }
}
