export interface HostPort {
  host: string
  port: number
}

export function parseHostPort(value: string): HostPort {
  // IPv6 bracketed: [::1]:8080
  if (value.startsWith("[")) {
    const end = value.indexOf("]")
    if (end === -1 || value[end + 1] !== ":") {
      throw new Error(`invalid host:port "${value}"`)
    }
    const host = value.slice(1, end)
    const port = parseInt(value.slice(end + 2), 10)
    if (isNaN(port)) throw new Error(`invalid port in "${value}"`)
    return { host, port }
  }
  const idx = value.lastIndexOf(":")
  if (idx === -1) throw new Error(`invalid host:port "${value}"`)
  const host = value.slice(0, idx)
  const port = parseInt(value.slice(idx + 1), 10)
  if (!host || isNaN(port)) throw new Error(`invalid host:port "${value}"`)
  return { host, port }
}
