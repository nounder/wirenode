import * as NNet from "node:net"
import type { StreamPair } from "../net/Bridge.ts"
import { bridge } from "../net/Bridge.ts"

export interface TcpClientTunnelOptions {
  bindAddress: string
  target: string
  dial: (host: string, port: number) => Promise<StreamPair>
}

export interface TcpServerTunnelOptions {
  listenPort: number
  target: string
  listen: (port: number, cb: (socket: NNet.Socket) => void) => void
}

function parseHostPort(addr: string): { host: string; port: number } {
  const idx = addr.lastIndexOf(":")
  return {
    host: addr.slice(0, idx),
    port: parseInt(addr.slice(idx + 1), 10),
  }
}

export function startTcpClientTunnel(options: TcpClientTunnelOptions): Promise<void> {
  const { bindAddress, target, dial } = options
  const { host: targetHost, port: targetPort } = parseHostPort(target)

  return new Promise((resolve, reject) => {
    const { host, port } = parseHostPort(bindAddress)

    const server = NNet.createServer(async (client) => {
      let remote: StreamPair
      try {
        remote = await dial(targetHost, targetPort)
      } catch (err) {
        console.error(`TCP Client Tunnel to ${target}: ${err}`)
        client.destroy()
        return
      }

      bridge(client, remote)
    })

    server.listen(port, host, () => {
      console.log(`TCP Client Tunnel: ${bindAddress} -> ${target}`)
      resolve()
    })
    server.on("error", reject)
  })
}

export function startTcpServerTunnel(options: TcpServerTunnelOptions): void {
  const { target } = options
  const { host: targetHost, port: targetPort } = parseHostPort(target)

  options.listen(options.listenPort, (client) => {
    const remote = NNet.connect(targetPort, targetHost)

    client.pipe(remote)
    remote.pipe(client)
    client.on("error", () => remote.destroy())
    remote.on("error", () => client.destroy())
    client.on("close", () => remote.destroy())
    remote.on("close", () => client.destroy())
  })

  console.log(`TCP Server Tunnel: WG port ${options.listenPort} -> ${target}`)
}
