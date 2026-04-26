export type Address =
  | { kind: "ipv4"; host: string; port: number }
  | { kind: "ipv6"; host: string; port: number }
  | { kind: "hostname"; host: string; port: number }

export function parse(value: string): Address {
  if (value.startsWith("[")) {
    const end = value.indexOf("]")
    if (end === -1 || value[end + 1] !== ":") {
      throw new Error(`invalid host:port "${value}"`)
    }
    const host = value.slice(1, end)
    const port = parseInt(value.slice(end + 2), 10)
    if (isNaN(port)) throw new Error(`invalid port in "${value}"`)
    return { kind: "ipv6", host, port }
  }
  const idx = value.lastIndexOf(":")
  if (idx === -1) throw new Error(`invalid host:port "${value}"`)
  const host = value.slice(0, idx)
  const port = parseInt(value.slice(idx + 1), 10)
  if (!host || isNaN(port)) throw new Error(`invalid host:port "${value}"`)
  return { kind: classify(host), host, port }
}

export function format(addr: Address): string {
  return addr.kind === "ipv6" ? `[${addr.host}]:${addr.port}` : `${addr.host}:${addr.port}`
}

function classify(host: string): "ipv4" | "hostname" {
  return /^\d+\.\d+\.\d+\.\d+$/.test(host) ? "ipv4" : "hostname"
}
