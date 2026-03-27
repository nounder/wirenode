import { createServer, Socket, connect } from "net"
import type { Duplex } from "stream"

export interface TCPClientTunnelOptions {
  bindAddress: string
  target: string
  dial: (host: string, port: number) => Promise<Duplex>
}

export interface TCPServerTunnelOptions {
  listenPort: number
  target: string
  listen: (port: number, cb: (socket: Socket) => void) => void
}

function parseHostPort(addr: string): { host: string; port: number } {
  const idx = addr.lastIndexOf(":")
  return {
    host: addr.slice(0, idx),
    port: parseInt(addr.slice(idx + 1), 10),
  }
}

export function startTCPClientTunnel(options: TCPClientTunnelOptions): Promise<void> {
  const { bindAddress, target, dial } = options
  const { host: targetHost, port: targetPort } = parseHostPort(target)

  return new Promise((resolve, reject) => {
    const { host, port } = parseHostPort(bindAddress)

    const server = createServer(async (client) => {
      let remote: Duplex
      try {
        remote = await dial(targetHost, targetPort)
      } catch (err) {
        console.error(`TCP Client Tunnel to ${target}: ${err}`)
        client.destroy()
        return
      }

      client.pipe(remote)
      remote.pipe(client)
      client.on("error", () => remote.destroy())
      remote.on("error", () => client.destroy())
      client.on("close", () => remote.destroy())
      remote.on("close", () => client.destroy())
    })

    server.listen(port, host, () => {
      console.log(`TCP Client Tunnel: ${bindAddress} -> ${target}`)
      resolve()
    })
    server.on("error", reject)
  })
}

export function startTCPServerTunnel(options: TCPServerTunnelOptions): void {
  const { target } = options
  const { host: targetHost, port: targetPort } = parseHostPort(target)

  options.listen(options.listenPort, (client) => {
    const remote = connect(targetPort, targetHost)

    client.pipe(remote)
    remote.pipe(client)
    client.on("error", () => remote.destroy())
    remote.on("error", () => client.destroy())
    client.on("close", () => remote.destroy())
    remote.on("close", () => client.destroy())
  })

  console.log(`TCP Server Tunnel: WG port ${options.listenPort} -> ${target}`)
}
