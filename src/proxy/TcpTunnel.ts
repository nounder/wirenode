import * as NNet from "node:net"
import type { StreamPair } from "../net/Bridge.ts"
import { bridge } from "../net/Bridge.ts"

export interface ClientOptions {
  host: string
  port: number
  targetHost: string
  targetPort: number
  dial: (host: string, port: number) => Promise<StreamPair>
}

export interface ServerOptions {
  listenPort: number
  targetHost: string
  targetPort: number
  listen: (port: number, cb: (socket: NNet.Socket) => void) => void
}

export async function serveClient(options: ClientOptions) {
  const server = NNet.createServer(async (client) => {
    let remote: StreamPair
    try {
      remote = await options.dial(options.targetHost, options.targetPort)
    } catch (err) {
      console.error(`TCP Client Tunnel to ${options.targetHost}:${options.targetPort}: ${err}`)
      client.destroy()
      return
    }

    bridge(client, remote)
  })

  await new Promise<void>((resolve, reject) => {
    server.listen(options.port, options.host, () => resolve())
    server.on("error", reject)
  })
  console.log(
    `TCP Client Tunnel: ${options.host}:${options.port} -> ${options.targetHost}:${options.targetPort}`,
  )

  return {
    stop: () =>
      new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()))
      }),
  }
}

export function serveServer(options: ServerOptions): void {
  options.listen(options.listenPort, (client) => {
    const remote = NNet.connect(options.targetPort, options.targetHost)

    client.pipe(remote)
    remote.pipe(client)
    client.on("error", () => remote.destroy())
    remote.on("error", () => client.destroy())
    client.on("close", () => remote.destroy())
    remote.on("close", () => client.destroy())
  })

  console.log(
    `TCP Server Tunnel: WG port ${options.listenPort} -> ${options.targetHost}:${options.targetPort}`,
  )
}
