#!/usr/bin/env bun
/**
 * wireproxy — WireGuard userspace client with SOCKS5/HTTP proxy support.
 * Compatible with pufferffish/wireproxy configuration format.
 */
import * as Config from "./wireguard/Config.ts"
import * as Wireproxy from "./Wireproxy.ts"
import * as Device from "./wireguard/Device.ts"

export * as Config from "./wireguard/Config.ts"
export * as Peer from "./wireguard/Peer.ts"
export * as Device from "./wireguard/Device.ts"
export * as VirtualTun from "./net/VirtualTun.ts"
export * as Wireproxy from "./Wireproxy.ts"
export * as Http from "./proxy/Http.ts"
export * as Socks5 from "./proxy/Socks5.ts"
export * as TcpTunnel from "./proxy/TcpTunnel.ts"
export * as UdpTunnel from "./proxy/UdpTunnel.ts"
export * as Result from "./Result.ts"

if (import.meta.main) {
  const args = process.argv.slice(2)

  let configPath = ""
  let configTest = false
  let silent = false
  let daemon = false
  let infoAddress = ""
  let showVersion = false
  let showHelp = false
  const overrides: string[] = []

  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!
    switch (arg) {
      case "-h":
      case "--help":
        showHelp = true
        break
      case "-v":
      case "--version":
        showVersion = true
        break
      case "-n":
      case "--configtest":
        configTest = true
        break
      case "-s":
      case "--silent":
        silent = true
        break
      case "-d":
      case "--daemon":
        daemon = true
        break
      case "-c":
      case "--config":
        configPath = args[++i] ?? ""
        break
      case "-i":
      case "--info":
        infoAddress = args[++i] ?? ""
        break
      case "-o":
      case "--override":
        overrides.push(args[++i] ?? "")
        break
      default:
        if (!arg.startsWith("-") && !configPath) {
          configPath = arg
        } else {
          console.error(`Unknown option: ${arg}`)
          process.exit(1)
        }
    }
  }

  if (showVersion) {
    console.log("wireproxy (wirenode) 0.1.0")
    process.exit(0)
  }

  if (showHelp || !configPath) {
    console.log(`wireproxy — WireGuard userspace client with proxy support

Usage:
  wireproxy -c <config-file> [options]
  wireproxy <config-file> [options]

Options:
  -c, --config <path>    Path to configuration file
  -n, --configtest       Validate configuration file and exit
  -s, --silent           Suppress log output
  -d, --daemon           Run in background (daemonize)
  -i, --info <addr:port> Expose health/status endpoint
  -o, --override <S.K=V> Override a config value (repeatable, e.g. HTTP.BindAddress=127.0.0.1:8080)
  -v, --version          Show version
  -h, --help             Show this help
`)
    process.exit(showHelp ? 0 : 1)
  }

  let configText: string
  try {
    configText = await Bun.file(configPath).text()
  } catch {
    console.error(`Cannot read config file: ${configPath}`)
    process.exit(1)
  }

  const sectionsResult = Config.parseSections(configText)
  if (!sectionsResult.ok) {
    console.error(`Configuration error: ${sectionsResult.error.message}`)
    process.exit(1)
  }

  const overrideResult = applyOverrides(sectionsResult.value, overrides)
  if (!overrideResult.ok) {
    console.error(`Configuration error: ${overrideResult.error}`)
    process.exit(1)
  }

  const configResult = Config.build(sectionsResult.value)
  if (!configResult.ok) {
    console.error(`Configuration error: ${configResult.error.message}`)
    process.exit(1)
  }

  const config = configResult.value
  const cliValidation = validateCliConfig(config)
  if (!cliValidation.ok) {
    console.error(`Configuration error: ${cliValidation.error}`)
    process.exit(1)
  }

  if (configTest) {
    console.log("Configuration is valid.")
    process.exit(0)
  }

  if (daemon) {
    const child = Bun.spawn(
      ["bun", "run", import.meta.path, "-c", configPath, "-s"],
      {
        stdio: ["ignore", "ignore", "ignore"],
        env: process.env,
      },
    )
    child.unref()
    console.log(`wireproxy started in background (pid ${child.pid})`)
    process.exit(0)
  }

  if (silent) {
    console.log = () => {}
    console.error = () => {}
  }

  const wpResult = await Wireproxy.open(config)
  if (!wpResult.ok) {
    console.error(`Failed to start: ${wpResult.error.message}`)
    process.exit(1)
  }
  const wp = wpResult.value

  if (infoAddress) {
    const [host, portStr] = infoAddress.split(":")
    const port = parseInt(portStr!, 10)
    Bun.serve({
      hostname: host,
      port,
      fetch() {
        const peers = Device.getPeers(wp.device)
        const status = {
          running: true,
          peers: peers.map((p) => ({
            publicKey: p.publicKeyHex.slice(0, 16) + "...",
            endpoint: p.endpoint,
            lastHandshakeAttempt: p.lastHandshakeAttempt,
          })),
        }
        return new Response(JSON.stringify(status, null, 2), {
          headers: { "Content-Type": "application/json" },
        })
      },
    })
    if (!silent) console.log(`Health endpoint on ${infoAddress}`)
  }

  process.on("SIGINT", async () => {
    if (!silent) console.log("\nShutting down...")
    await Wireproxy.close(wp)
    process.exit(0)
  })

  process.on("SIGTERM", async () => {
    await Wireproxy.close(wp)
    process.exit(0)
  })
}

function applyOverrides(
  sections: Config.Section[],
  overrides: string[],
): { ok: true } | { ok: false; error: string } {
  for (const raw of overrides) {
    const eq = raw.indexOf("=")
    const dot = raw.indexOf(".")
    if (dot === -1 || eq === -1 || dot > eq) {
      return { ok: false, error: `invalid override "${raw}", expected Section.Key=Value` }
    }
    const sectionName = raw.slice(0, dot).trim().toLowerCase()
    const key = raw.slice(dot + 1, eq).trim().toLowerCase()
    const value = raw.slice(eq + 1).trim()
    if (!sectionName || !key) {
      return { ok: false, error: `invalid override "${raw}", expected Section.Key=Value` }
    }

    let section = sections.find((s) => s.name === sectionName)
    if (!section) {
      section = { name: sectionName, line: 0, entries: {} }
      sections.push(section)
    }
    section.entries[key] = { value, line: 0 }
  }
  return { ok: true }
}

function validateCliConfig(config: Config.Config): { ok: true } | { ok: false; error: string } {
  const runnable = config.routines.filter(
    (routine) =>
      routine.type === "socks5" ||
      routine.type === "http" ||
      routine.type === "tcpClient" ||
      routine.type === "udp",
  )

  if (runnable.length === 0) {
    return {
      ok: false,
      error:
        "no runnable proxy/tunnel section configured; add [Socks5], [HTTP], [TCPClientTunnel], or [UDPProxyTunnel]",
    }
  }

  return { ok: true }
}
