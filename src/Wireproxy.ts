/**
 * WireGuard client with SOCKS5/HTTP proxy support.
 */
import * as Config from "./wireguard/Config.ts"
import * as Device from "./wireguard/Device.ts"
import * as VirtualTun from "./net/VirtualTun.ts"
import type { StreamPair } from "./net/Bridge.ts"
import * as Address from "./net/Address.ts"
import * as Socks5 from "./proxy/Socks5.ts"
import * as Http from "./proxy/Http.ts"
import * as TcpTunnel from "./proxy/TcpTunnel.ts"
import * as UdpTunnel from "./proxy/UdpTunnel.ts"
import * as Result from "./Result.ts"

export interface WireproxyResource extends AsyncDisposable {
  config: Config.Config
  device: Device.DeviceResource
  vt: VirtualTun.VirtualTunResource
  _handles: { stop: () => Promise<void> }[]
}

export async function open(config: Config.Config): Promise<Result.Result<WireproxyResource>> {
  const conf = config

  const deviceResult = await Device.open({
    privateKey: conf.interface.privateKey,
    listenPort: conf.interface.listenPort,
    peers: conf.peers,
    mtu: conf.interface.mtu,
  })
  if (!deviceResult.ok) return deviceResult
  const device = deviceResult.value

  console.log(`WireGuard device up on port ${Device.getPort(device)}`)

  const vt = VirtualTun.open({
    device,
    addresses: conf.interface.address,
    dns: conf.interface.dns,
    resolveConfig: conf.resolve,
  })

  for (const peer of Device.getPeers(device)) {
    if (peer.endpoint) {
      Device.initiateHandshake(device, peer)
    }
  }

  device.events.on("handshakeComplete", (peer) => {
    console.log(`Handshake complete with peer ${peer.publicKeyHex.slice(0, 16)}...`)
  })

  device.events.on("error", (err) => {
    console.error(`WireGuard error: ${err.message}`)
  })

  const dial = async (host: string, port: number): Promise<StreamPair> => {
    return VirtualTun.dial(vt, host, port)
  }

  const promises: Promise<{ stop: () => Promise<void> }>[] = []

  for (const routine of conf.routines) {
    switch (routine.type) {
      case "socks5": {
        const bind = Address.parse(routine.bindAddress)
        promises.push(
          Socks5.serve({
            host: bind.host,
            port: bind.port,
            username: routine.username || undefined,
            password: routine.password || undefined,
            dial,
          }),
        )
        break
      }

      case "http": {
        const bind = Address.parse(routine.bindAddress)
        promises.push(
          Http.serve({
            host: bind.host,
            port: bind.port,
            username: routine.username || undefined,
            password: routine.password || undefined,
            certFile: routine.certFile || undefined,
            keyFile: routine.keyFile || undefined,
            dial,
          }),
        )
        break
      }

      case "tcpClient": {
        const bind = Address.parse(routine.bindAddress)
        const target = Address.parse(routine.target)
        promises.push(
          TcpTunnel.serveClient({
            host: bind.host,
            port: bind.port,
            targetHost: target.host,
            targetPort: target.port,
            dial,
          }),
        )
        break
      }

      case "udp": {
        const bind = Address.parse(routine.bindAddress)
        const target = Address.parse(routine.target)
        promises.push(
          UdpTunnel.serve({
            host: bind.host,
            port: bind.port,
            targetHost: target.host,
            targetPort: target.port,
            inactivityTimeout: routine.inactivityTimeout,
            dial: (t) => VirtualTun.dialUdp(vt, t),
          }),
        )
        break
      }

      case "stdio":
        console.log(`STDIO tunnel to ${routine.target} — not yet implemented`)
        break

      case "tcpServer":
        console.log(
          `TCP Server tunnel on port ${routine.listenPort} -> ${routine.target} — not yet implemented`,
        )
        break
    }
  }

  let handles: { stop: () => Promise<void> }[]
  try {
    handles = await Promise.all(promises)
  } catch (e) {
    VirtualTun.close(vt)
    await Device.close(device)
    return Result.error(e instanceof Error ? e : new Error(String(e)))
  }

  const resource: WireproxyResource = {
    config,
    device,
    vt,
    _handles: handles,
    [Symbol.asyncDispose]: () => close(resource),
  }
  return Result.ok(resource)
}

export async function close(self: WireproxyResource): Promise<void> {
  await Promise.all(self._handles.map((h) => h.stop()))
  self._handles = []
  await Device.close(self.device)
  VirtualTun.close(self.vt)
}
