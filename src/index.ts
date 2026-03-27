export { Wireproxy } from "./Wireproxy.ts"
export { Device } from "./wireguard/Device.ts"
export { Peer } from "./wireguard/Peer.ts"
export type { DeviceConfig } from "./wireguard/Device.ts"
export type { PeerConfig } from "./wireguard/Peer.ts"
export { parseConfig } from "./wireguard/Config.ts"
export type { Configuration, InterfaceConfig, RoutineConfig } from "./wireguard/Config.ts"
export { VirtualTun } from "./net/VirtualTun.ts"

if (import.meta.main) {
  const args = process.argv.slice(2)

  if (args.length === 0 || args.includes("--help") || args.includes("-h")) {
    console.log(`wirenode — WireGuard userspace client with proxy support

Usage:
  bun run src/index.ts <config-file>       Start wireproxy with config
  bun run src/index.ts --configtest <file> Validate config without starting

Options:
  --help, -h       Show this help
  --configtest     Validate configuration file only
`)
    process.exit(0)
  }

  const configTest = args.includes("--configtest")
  const configPath = args.find((a) => !a.startsWith("-"))!

  const { Wireproxy } = await import("./Wireproxy.ts")
  const { parseConfig } = await import("./wireguard/Config.ts")

  const configText = await Bun.file(configPath).text()

  if (configTest) {
    try {
      parseConfig(configText)
      console.log("Configuration is valid.")
      process.exit(0)
    } catch (err: any) {
      console.error(`Configuration error: ${err.message}`)
      process.exit(1)
    }
  }

  const wp = new Wireproxy(configText)

  process.on("SIGINT", async () => {
    console.log("\nShutting down...")
    await wp.stop()
    process.exit(0)
  })

  process.on("SIGTERM", async () => {
    await wp.stop()
    process.exit(0)
  })

  try {
    await wp.start()
  } catch (err: any) {
    console.error(`Failed to start: ${err.message}`)
    process.exit(1)
  }
}
