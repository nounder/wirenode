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

export interface ConfigError {
  message: string
  line?: number
  section?: string
  key?: string
}

type Result<T> =
  | { ok: true; value: T }
  | { ok: false; error: ConfigError }

export type ConfigResult = Result<Configuration>

interface SectionEntry {
  value: string
  line: number
}

interface Section {
  name: string
  line: number
  entries: Map<string, SectionEntry>
}

const KnownSections = new Map<string, ReadonlySet<string>>([
  [
    "interface",
    new Set([
      "privatekey",
      "address",
      "dns",
      "mtu",
      "listenport",
      "checkalive",
      "checkaliveinterval",
    ]),
  ],
  [
    "peer",
    new Set(["publickey", "presharedkey", "endpoint", "persistentkeepalive", "allowedips"]),
  ],
  ["tcpclienttunnel", new Set(["bindaddress", "target"])],
  ["tcpservertunnel", new Set(["listenport", "target"])],
  ["stdiotunnel", new Set(["target"])],
  ["socks5", new Set(["bindaddress", "username", "password"])],
  ["http", new Set(["bindaddress", "username", "password", "certfile", "keyfile"])],
  ["udpproxytunnel", new Set(["bindaddress", "target", "inactivitytimeout"])],
  ["resolve", new Set(["resolvestrategy"])],
])

function displaySectionName(name: string): string {
  return name || "<root>"
}

function keyMeta(section: Section, key: string): Pick<ConfigError, "line" | "section" | "key"> {
  return {
    line: section.entries.get(key)?.line ?? section.line,
    section: displaySectionName(section.name),
    key,
  }
}

export function formatConfigError(error: ConfigError): string {
  const details: string[] = []
  if (error.line !== undefined) details.push(`line ${error.line}`)
  if (error.section !== undefined) details.push(`section [${error.section}]`)
  if (error.key !== undefined) details.push(`key ${error.key}`)
  return details.length > 0 ? `${error.message} (${details.join(", ")})` : error.message
}

function parseSections(text: string): Result<Section[]> {
  const sections: Section[] = []
  let current: Section | null = null

  const lines = text.split("\n")
  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i]!
    const line = rawLine.trim()
    if (line === "" || line.startsWith("#") || line.startsWith(";")) continue

    const sectionMatch = line.match(/^\[(.+)\]$/)
    if (sectionMatch) {
      const name = sectionMatch[1]!.trim().toLowerCase()
      if (!name) {
        return {
          ok: false,
          error: {
            message: `invalid section header: ${line}`,
            line: i + 1,
          },
        }
      }
      current = { name, line: i + 1, entries: new Map() }
      sections.push(current)
      continue
    }

    if (line.startsWith("[") || line.endsWith("]")) {
      return {
        ok: false,
        error: {
          message: `invalid section header: ${line}`,
          line: i + 1,
        },
      }
    }

    const eqIdx = line.indexOf("=")
    if (eqIdx === -1) {
      return {
        ok: false,
        error: {
          message: "invalid config line: expected key = value",
          line: i + 1,
        },
      }
    }

    if (!current) {
      // Root-level key
      current = { name: "", line: i + 1, entries: new Map() }
      sections.push(current)
    }

    const key = line.slice(0, eqIdx).trim().toLowerCase()
    const value = line.slice(eqIdx + 1).trim()
    if (!key) {
      return {
        ok: false,
        error: {
          message: "invalid config line: empty key",
          line: i + 1,
        },
      }
    }
    current.entries.set(key, { value, line: i + 1 })
  }

  return { ok: true, value: sections }
}

function validateKnownConfig(sections: Section[]): Result<void> {
  for (const section of sections) {
    const allowedKeys = KnownSections.get(section.name)
    if (!allowedKeys) {
      const name = section.name || "<root>"
      return {
        ok: false,
        error: {
          message: `unknown config section [${name}]`,
          line: section.line,
          section: name,
        },
      }
    }

    for (const [key, entry] of section.entries) {
      if (allowedKeys.has(key)) continue

      return {
        ok: false,
        error: {
          message: `unknown config key [${displaySectionName(section.name)}].${key}`,
          line: entry.line,
          section: displaySectionName(section.name),
          key,
        },
      }
    }
  }

  return { ok: true, value: undefined }
}

function resolveEnvVar(
  value: string,
  meta: Pick<ConfigError, "line" | "section" | "key">,
): Result<string> {
  if (value.startsWith("$$")) return { ok: true, value: "$" + value.slice(2) }
  if (value.startsWith("$")) {
    const envVal = process.env[value.slice(1)]
    if (envVal === undefined) {
      return {
        ok: false,
        error: {
          message: `unset environment variable: ${value}`,
          ...meta,
        },
      }
    }
    return { ok: true, value: envVal }
  }
  return { ok: true, value }
}

function getString(section: Section, key: string): Result<string> {
  const entry = section.entries.get(key)
  if (entry === undefined) return { ok: true, value: "" }
  return resolveEnvVar(entry.value, keyMeta(section, key))
}

function getRequiredString(section: Section, key: string, label: string): Result<string> {
  const value = getString(section, key)
  if (!value.ok) return value
  if (value.value) return value
  return {
    ok: false,
    error: {
      message: `${label} is required`,
      ...keyMeta(section, key),
    },
  }
}

function getOptionalInt(section: Section, key: string): Result<number | undefined> {
  const entry = section.entries.get(key)
  if (entry === undefined) return { ok: true, value: undefined }
  const value = resolveEnvVar(entry.value, keyMeta(section, key))
  if (!value.ok) return value

  const n = parseInt(value.value, 10)
  if (isNaN(n)) {
    return {
      ok: false,
      error: {
        message: `invalid integer for ${key}: ${value.value}`,
        ...keyMeta(section, key),
      },
    }
  }
  return { ok: true, value: n }
}

function getInt(section: Section, key: string, defaultVal: number): Result<number> {
  const value = getOptionalInt(section, key)
  if (!value.ok) return value
  return { ok: true, value: value.value ?? defaultVal }
}

function base64ToBytes(
  b64: string,
  meta: Pick<ConfigError, "line" | "section" | "key">,
): Result<Uint8Array> {
  let buf: Buffer
  try {
    buf = Buffer.from(b64, "base64")
  } catch {
    return {
      ok: false,
      error: {
        message: "invalid base64 key",
        ...meta,
      },
    }
  }

  if (buf.length !== 32) {
    return {
      ok: false,
      error: {
        message: "key should be 32 bytes",
        ...meta,
      },
    }
  }
  return { ok: true, value: new Uint8Array(buf) }
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

function getSection(sections: Section[], name: string): Section[] {
  return sections.filter((s) => s.name === name)
}

function parseResolveStrategy(
  value: string,
  meta: Pick<ConfigError, "line" | "section" | "key">,
): Result<ResolveConfig["resolveStrategy"]> {
  if (value === "auto" || value === "ipv4" || value === "ipv6") {
    return { ok: true, value }
  }
  return {
    ok: false,
    error: {
      message: `invalid resolve strategy: ${value}`,
      ...meta,
    },
  }
}

export function parseConfig(text: string): ConfigResult {
  const parsed = parseSections(text)
  if (!parsed.ok) return parsed

  const sections = parsed.value
  const known = validateKnownConfig(sections)
  if (!known.ok) return known

  // Parse Interface
  const ifaceSections = getSection(sections, "interface")
  if (ifaceSections.length !== 1) {
    return {
      ok: false,
      error: {
        message: "exactly one [Interface] section required",
      },
    }
  }
  const iface = ifaceSections[0]!

  const privateKeyB64 = getRequiredString(iface, "privatekey", "PrivateKey")
  if (!privateKeyB64.ok) return privateKeyB64

  const privateKey = base64ToBytes(privateKeyB64.value, keyMeta(iface, "privatekey"))
  if (!privateKey.ok) return privateKey

  const address = getString(iface, "address")
  if (!address.ok) return address
  const dns = getString(iface, "dns")
  if (!dns.ok) return dns
  const mtu = getInt(iface, "mtu", 1420)
  if (!mtu.ok) return mtu
  const checkAlive = getString(iface, "checkalive")
  if (!checkAlive.ok) return checkAlive
  const checkAliveInterval = getInt(iface, "checkaliveinterval", 5)
  if (!checkAliveInterval.ok) return checkAliveInterval

  const ifaceConfig: InterfaceConfig = {
    privateKey: privateKey.value,
    address: parseCIDRAddresses(address.value),
    dns: parseAddressList(dns.value),
    mtu: mtu.value,
    checkAlive: parseAddressList(checkAlive.value),
    checkAliveInterval: checkAliveInterval.value,
  }

  const listenPort = getOptionalInt(iface, "listenport")
  if (!listenPort.ok) return listenPort
  if (listenPort.value !== undefined) ifaceConfig.listenPort = listenPort.value

  // Parse Peers
  const peerSections = getSection(sections, "peer")
  if (peerSections.length < 1) {
    return {
      ok: false,
      error: {
        message: "at least one [Peer] section required",
      },
    }
  }

  const peers: PeerConfig[] = []
  for (const ps of peerSections) {
    const publicKeyB64 = getRequiredString(ps, "publickey", "PublicKey")
    if (!publicKeyB64.ok) return publicKeyB64

    const publicKey = base64ToBytes(publicKeyB64.value, keyMeta(ps, "publickey"))
    if (!publicKey.ok) return publicKey

    const presharedKeyB64 = getString(ps, "presharedkey")
    if (!presharedKeyB64.ok) return presharedKeyB64
    const presharedKey: Result<Uint8Array> = presharedKeyB64.value
      ? base64ToBytes(presharedKeyB64.value, keyMeta(ps, "presharedkey"))
      : { ok: true, value: new Uint8Array(32) }
    if (!presharedKey.ok) return presharedKey

    const endpoint = getString(ps, "endpoint")
    if (!endpoint.ok) return endpoint
    const keepAlive = getInt(ps, "persistentkeepalive", 0)
    if (!keepAlive.ok) return keepAlive
    const allowedIPsValue = getString(ps, "allowedips")
    if (!allowedIPsValue.ok) return allowedIPsValue
    const allowedIPs = parseAllowedIPs(allowedIPsValue.value)

    peers.push({
      publicKey: publicKey.value,
      presharedKey: presharedKey.value,
      endpoint: endpoint.value || undefined,
      persistentKeepalive: keepAlive.value,
      allowedIPs: allowedIPs.length > 0 ? allowedIPs : ["0.0.0.0/0", "::/0"],
    })
  }

  // Parse routines
  const routines: RoutineConfig[] = []

  for (const s of getSection(sections, "tcpclienttunnel")) {
    const bindAddress = getString(s, "bindaddress")
    if (!bindAddress.ok) return bindAddress
    const target = getString(s, "target")
    if (!target.ok) return target

    routines.push({
      type: "tcpClient",
      bindAddress: bindAddress.value,
      target: target.value,
    })
  }

  for (const s of getSection(sections, "tcpservertunnel")) {
    const listenPort = getInt(s, "listenport", 0)
    if (!listenPort.ok) return listenPort
    const target = getString(s, "target")
    if (!target.ok) return target

    routines.push({
      type: "tcpServer",
      listenPort: listenPort.value,
      target: target.value,
    })
  }

  for (const s of getSection(sections, "stdiotunnel")) {
    const target = getString(s, "target")
    if (!target.ok) return target

    routines.push({
      type: "stdio",
      target: target.value,
    })
  }

  for (const s of getSection(sections, "socks5")) {
    const bindAddress = getString(s, "bindaddress")
    if (!bindAddress.ok) return bindAddress
    const username = getString(s, "username")
    if (!username.ok) return username
    const password = getString(s, "password")
    if (!password.ok) return password

    routines.push({
      type: "socks5",
      bindAddress: bindAddress.value,
      username: username.value,
      password: password.value,
    })
  }

  for (const s of getSection(sections, "http")) {
    const bindAddress = getString(s, "bindaddress")
    if (!bindAddress.ok) return bindAddress
    const username = getString(s, "username")
    if (!username.ok) return username
    const password = getString(s, "password")
    if (!password.ok) return password
    const certFile = getString(s, "certfile")
    if (!certFile.ok) return certFile
    const keyFile = getString(s, "keyfile")
    if (!keyFile.ok) return keyFile

    routines.push({
      type: "http",
      bindAddress: bindAddress.value,
      username: username.value,
      password: password.value,
      certFile: certFile.value,
      keyFile: keyFile.value,
    })
  }

  for (const s of getSection(sections, "udpproxytunnel")) {
    const bindAddress = getString(s, "bindaddress")
    if (!bindAddress.ok) return bindAddress
    const target = getString(s, "target")
    if (!target.ok) return target
    const inactivityTimeout = getInt(s, "inactivitytimeout", 0)
    if (!inactivityTimeout.ok) return inactivityTimeout

    routines.push({
      type: "udp",
      bindAddress: bindAddress.value,
      target: target.value,
      inactivityTimeout: inactivityTimeout.value,
    })
  }

  let resolve: ResolveConfig = { resolveStrategy: "auto" }
  const resolveSections = getSection(sections, "resolve")
  if (resolveSections.length > 0) {
    const section = resolveSections[0]!
    const strategyValue = getString(section, "resolvestrategy")
    if (!strategyValue.ok) return strategyValue
    const strategy = parseResolveStrategy(
      strategyValue.value || "auto",
      keyMeta(section, "resolvestrategy"),
    )
    if (!strategy.ok) return strategy
    resolve = { resolveStrategy: strategy.value }
  }

  return {
    ok: true,
    value: {
      interface: ifaceConfig,
      peers,
      routines,
      resolve,
    },
  }
}
