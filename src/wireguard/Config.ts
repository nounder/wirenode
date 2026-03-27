/**
 * WireGuard/wireproxy ini configuration parser
 */
import type { PeerConfig } from "./Peer.ts"

export interface InterfaceConfig {
  privateKey: Uint8Array
  address: string[]
  dns: string[]
  mtu: number
  listenPort?: number
  checkAlive: string[]
  checkAliveInterval: number
}

export interface TcpClientTunnelConfig {
  type: "tcpClient"
  bindAddress: string
  target: string
}

export interface TcpServerTunnelConfig {
  type: "tcpServer"
  listenPort: number
  target: string
}

export interface Socks5Config {
  type: "socks5"
  bindAddress: string
  username: string
  password: string
}

export interface HttpProxyConfig {
  type: "http"
  bindAddress: string
  username: string
  password: string
  certFile: string
  keyFile: string
}

export interface UdpProxyConfig {
  type: "udp"
  bindAddress: string
  target: string
  inactivityTimeout: number
}

export interface StdioTunnelConfig {
  type: "stdio"
  target: string
}

export type RoutineConfig =
  | TcpClientTunnelConfig
  | TcpServerTunnelConfig
  | Socks5Config
  | HttpProxyConfig
  | UdpProxyConfig
  | StdioTunnelConfig

export interface ResolveConfig {
  resolveStrategy: "auto" | "ipv4" | "ipv6"
}

export interface Configuration {
  interface: InterfaceConfig
  peers: PeerConfig[]
  routines: RoutineConfig[]
  resolve: ResolveConfig
}

interface Section {
  name: string
  entries: Map<string, string>
}

function parseSections(text: string): Section[] {
  const sections: Section[] = []
  let current: Section | null = null

  for (const rawLine of text.split("\n")) {
    const line = rawLine.trim()
    if (line === "" || line.startsWith("#") || line.startsWith(";")) continue

    const sectionMatch = line.match(/^\[(.+)\]$/)
    if (sectionMatch) {
      current = { name: sectionMatch[1]!.toLowerCase(), entries: new Map() }
      sections.push(current)
      continue
    }

    if (!current) {
      // Root-level key
      current = { name: "", entries: new Map() }
      sections.push(current)
    }

    const eqIdx = line.indexOf("=")
    if (eqIdx === -1) continue

    const key = line.slice(0, eqIdx).trim().toLowerCase()
    const value = line.slice(eqIdx + 1).trim()
    current.entries.set(key, value)
  }

  return sections
}

function resolveEnvVar(value: string): string {
  if (value.startsWith("$$")) return "$" + value.slice(2)
  if (value.startsWith("$")) {
    const envVal = process.env[value.slice(1)]
    if (envVal === undefined) throw new Error(`unset environment variable: ${value}`)
    return envVal
  }
  return value
}

function getString(section: Section, key: string): string {
  const val = section.entries.get(key)
  if (val === undefined) return ""
  return resolveEnvVar(val)
}

function getInt(section: Section, key: string, defaultVal: number): number {
  const val = section.entries.get(key)
  if (val === undefined) return defaultVal
  const n = parseInt(val, 10)
  if (isNaN(n)) throw new Error(`invalid integer for ${key}: ${val}`)
  return n
}

function base64ToBytes(b64: string): Uint8Array {
  const buf = Buffer.from(b64, "base64")
  if (buf.length !== 32) throw new Error(`key should be 32 bytes: ${b64}`)
  return new Uint8Array(buf)
}

function parseAddressList(value: string): string[] {
  if (!value) return []
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
}

function parseCIDRAddresses(value: string): string[] {
  if (!value) return []
  return value
    .split(",")
    .map((s) => {
      s = s.trim()
      // Strip CIDR prefix for IP addresses
      if (s.includes("/")) {
        return s.split("/")[0]!
      }
      return s
    })
    .filter(Boolean)
}

function parseAllowedIPs(value: string): string[] {
  if (!value) return []
  return value
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
}

export function parseConfig(text: string): Configuration {
  const sections = parseSections(text)

  // Parse Interface
  const ifaceSections = sections.filter((s) => s.name === "interface")
  if (ifaceSections.length !== 1) throw new Error("exactly one [Interface] section required")
  const iface = ifaceSections[0]!

  const privateKeyB64 = getString(iface, "privatekey")
  if (!privateKeyB64) throw new Error("PrivateKey is required")

  const ifaceConfig: InterfaceConfig = {
    privateKey: base64ToBytes(privateKeyB64),
    address: parseCIDRAddresses(getString(iface, "address")),
    dns: parseAddressList(getString(iface, "dns")),
    mtu: getInt(iface, "mtu", 1420),
    checkAlive: parseAddressList(getString(iface, "checkalive")),
    checkAliveInterval: getInt(iface, "checkaliveinterval", 5),
  }

  const listenPort = iface.entries.get("listenport")
  if (listenPort) ifaceConfig.listenPort = parseInt(listenPort, 10)

  // Parse Peers
  const peerSections = sections.filter((s) => s.name === "peer")
  if (peerSections.length < 1) throw new Error("at least one [Peer] section required")

  const peers: PeerConfig[] = peerSections.map((ps) => {
    const publicKeyB64 = getString(ps, "publickey")
    if (!publicKeyB64) throw new Error("PublicKey is required for peer")

    const presharedKeyB64 = getString(ps, "presharedkey")
    const presharedKey = presharedKeyB64 ? base64ToBytes(presharedKeyB64) : new Uint8Array(32)

    const endpoint = getString(ps, "endpoint") || undefined
    const keepAlive = getInt(ps, "persistentkeepalive", 0)
    const allowedIPs = parseAllowedIPs(getString(ps, "allowedips"))

    return {
      publicKey: base64ToBytes(publicKeyB64),
      presharedKey,
      endpoint,
      persistentKeepalive: keepAlive,
      allowedIPs: allowedIPs.length > 0 ? allowedIPs : ["0.0.0.0/0", "::/0"],
    }
  })

  // Parse routines
  const routines: RoutineConfig[] = []

  for (const s of sections.filter((s) => s.name === "tcpclienttunnel")) {
    routines.push({
      type: "tcpClient",
      bindAddress: getString(s, "bindaddress"),
      target: getString(s, "target"),
    })
  }

  for (const s of sections.filter((s) => s.name === "tcpservertunnel")) {
    routines.push({
      type: "tcpServer",
      listenPort: getInt(s, "listenport", 0),
      target: getString(s, "target"),
    })
  }

  for (const s of sections.filter((s) => s.name === "stdiotunnel")) {
    routines.push({
      type: "stdio",
      target: getString(s, "target"),
    })
  }

  for (const s of sections.filter((s) => s.name === "socks5")) {
    routines.push({
      type: "socks5",
      bindAddress: getString(s, "bindaddress"),
      username: getString(s, "username"),
      password: getString(s, "password"),
    })
  }

  for (const s of sections.filter((s) => s.name === "http")) {
    routines.push({
      type: "http",
      bindAddress: getString(s, "bindaddress"),
      username: getString(s, "username"),
      password: getString(s, "password"),
      certFile: getString(s, "certfile"),
      keyFile: getString(s, "keyfile"),
    })
  }

  for (const s of sections.filter((s) => s.name === "udpproxytunnel")) {
    routines.push({
      type: "udp",
      bindAddress: getString(s, "bindaddress"),
      target: getString(s, "target"),
      inactivityTimeout: getInt(s, "inactivitytimeout", 0),
    })
  }

  let resolve: ResolveConfig = { resolveStrategy: "auto" }
  const resolveSections = sections.filter((s) => s.name === "resolve")
  if (resolveSections.length > 0) {
    const strategy = getString(resolveSections[0]!, "resolvestrategy") || "auto"
    resolve = { resolveStrategy: strategy as "auto" | "ipv4" | "ipv6" }
  }

  return {
    interface: ifaceConfig,
    peers,
    routines,
    resolve,
  }
}
