/**
 * WireGuard client with SOCKS5/HTTP proxy support.
 */
import * as Config from "./wireguard/Config.ts"
import { Device } from "./wireguard/Device.ts"
import { VirtualTun } from "./net/VirtualTun.ts"
import type { StreamPair } from "./net/Bridge.ts"
import * as Socks5 from "./proxy/Socks5.ts"
import * as Http from "./proxy/Http.ts"
import * as TcpTunnel from "./proxy/TcpTunnel.ts"
import * as UdpProxy from "./proxy/UdpProxy.ts"

export class Wireproxy {
  #device: Device | null = null
  #vt: VirtualTun | null = null
  #config: Config.Configuration

  constructor(config: Config.Configuration) {
    this.#config = config
  }

  async start(): Promise<void> {
    const conf = this.#config

    // Create WireGuard device
    this.#device = new Device({
      privateKey: conf.interface.privateKey,
      listenPort: conf.interface.listenPort,
      peers: conf.peers,
      mtu: conf.interface.mtu,
    })

    // Start device
    await this.#device.up()
    console.log(`WireGuard device up on port ${this.#device.getPort()}`)

    // Create virtual tun
    this.#vt = new VirtualTun({
      device: this.#device,
      addresses: conf.interface.address,
      dns: conf.interface.dns,
      resolveConfig: conf.resolve,
    })

    // Initiate handshakes with all peers that have endpoints
    for (const peer of this.#device.getPeers()) {
      if (peer.endpoint) {
        this.#device.initiateHandshake(peer)
      }
    }

    this.#device.on("handshakeComplete", (peer) => {
      console.log(`Handshake complete with peer ${peer.publicKeyHex.slice(0, 16)}...`)
    })

    this.#device.on("error", (err) => {
      console.error(`WireGuard error: ${err.message}`)
    })

    const dial = async (host: string, port: number): Promise<StreamPair> => {
      return this.#vt!.dial(host, port)
    }

    // Start all configured routines
    const promises: Promise<void>[] = []

    for (const routine of conf.routines) {
      switch (routine.type) {
        case "socks5":
          promises.push(
            Socks5.startSocks5({
              bindAddress: routine.bindAddress,
              username: routine.username || undefined,
              password: routine.password || undefined,
              dial,
            }),
          )
          break

        case "http":
          promises.push(
            Http.startHttpProxy({
              bindAddress: routine.bindAddress,
              username: routine.username || undefined,
              password: routine.password || undefined,
              certFile: routine.certFile || undefined,
              keyFile: routine.keyFile || undefined,
              dial,
            }),
          )
          break

        case "tcpClient":
          promises.push(
            TcpTunnel.startTcpClientTunnel({
              bindAddress: routine.bindAddress,
              target: routine.target,
              dial,
            }),
          )
          break

        case "udp":
          promises.push(
            UdpProxy.startUdpProxy({
              bindAddress: routine.bindAddress,
              target: routine.target,
              inactivityTimeout: routine.inactivityTimeout,
              dial: (target) => this.#vt!.dialUdp(target),
            }),
          )
          break

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

    await Promise.all(promises)
  }

  async stop(): Promise<void> {
    if (this.#device) {
      await this.#device.down()
      this.#device = null
    }
    this.#vt = null
  }

  getDevice(): Device | null {
    return this.#device
  }

  getVirtualTun(): VirtualTun | null {
    return this.#vt
  }
}
