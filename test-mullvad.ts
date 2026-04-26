/**
 * Integration test: connect to Mullvad VPN via WireGuard and verify IP changed.
 * Uses Bun's fetch with proxy option through an in-process HTTP proxy over the tunnel.
 *
 * Usage: bun run test-mullvad.ts /path/to/mullvad.conf
 */

import { parseConfig } from "./src/wireguard/Config.ts"
import { Device } from "./src/wireguard/Device.ts"
import { VirtualTun } from "./src/net/VirtualTun.ts"
import { startHttpProxy } from "./src/proxy/Http.ts"

const configPath = process.argv[2]
if (!configPath) {
  console.error("Usage: bun run test-mullvad.ts <config-file>")
  process.exit(1)
}

const configText = await Bun.file(configPath).text()
const conf = parseConfig(configText)

// Get our real IP first
console.log("Getting real IP...")
const realIPResp = await fetch("https://api.ipify.org?format=json")
const { ip: realIP } = (await realIPResp.json()) as { ip: string }
console.log(`Real IP: ${realIP}`)

// Create WireGuard device
const device = new Device({
  privateKey: conf.interface.privateKey,
  listenPort: conf.interface.listenPort,
  peers: conf.peers,
  mtu: conf.interface.mtu,
})

await device.up()
console.log(`WireGuard device up on port ${device.getPort()}`)

device.on("error", (err: Error) => {
  console.error(`WireGuard error: ${err.message}`)
})

// Create virtual tun with TCP stack
const vt = new VirtualTun({
  device,
  addresses: conf.interface.address,
  dns: conf.interface.dns,
  resolveConfig: conf.resolve,
})

// Initiate handshake
const peer = device.getPeers()[0]!
console.log(`Initiating handshake with ${peer.endpoint}...`)

await new Promise<void>((resolve, reject) => {
  const timeout = setTimeout(() => reject(new Error("handshake timed out after 10s")), 10_000)
  device.once("handshakeComplete", () => {
    clearTimeout(timeout)
    console.log("Handshake complete!")
    resolve()
  })
  device.initiateHandshake(peer)
})

// Start an in-process HTTP proxy that routes through the WireGuard tunnel
const proxyBind = "127.0.0.1:18199"
await startHttpProxy({
  bindAddress: proxyBind,
  dial: (host, port) => vt.dial(host, port),
})

// Use standard fetch with Bun's proxy option
const proxy = `http://${proxyBind}`

try {
  const res = await fetch("https://api.ipify.org/?format=json", { proxy })
  const { ip: tunnelIP } = (await res.json()) as { ip: string }

  console.log(`\nTunnel IP: ${tunnelIP}`)
  console.log(`Real IP:   ${realIP}`)

  if (tunnelIP !== realIP) {
    console.log("\n✅ SUCCESS: IP is different through the WireGuard tunnel!")
  } else {
    console.log("\n❌ FAIL: IP is the same — traffic may not be routing through the tunnel")
  }
} catch (err) {
  console.error(`Failed: ${err instanceof Error ? err.message : err}`)
}

await device.down()
process.exit(0)
