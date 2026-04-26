import { test, expect } from "bun:test"
import * as Config from "./Config.ts"

const sampleConfig = `
[Interface]
PrivateKey = YNqHbfBQKaGvzefJtfkbMuig9bLFPiuo1PKKTq1HE0g=
Address = 10.200.200.2/32
DNS = 10.200.200.1
MTU = 1420

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = my.server.com:51820
PersistentKeepalive = 25

[Socks5]
BindAddress = 127.0.0.1:25344
Username = testuser
Password = testpass

[http]
BindAddress = 127.0.0.1:25345

[TCPClientTunnel]
BindAddress = 127.0.0.1:25565
Target = remote.host:25565

[UDPProxyTunnel]
BindAddress = 127.0.0.1:53
Target = 1.1.1.1:53
InactivityTimeout = 30
`

test("parse config - interface section", () => {
  const result = Config.parseConfig(sampleConfig)
  expect(result.ok).toBe(true)
  if (!result.ok) return

  expect(result.value.interface.privateKey.length).toBe(32)
  expect(result.value.interface.address).toEqual(["10.200.200.2"])
  expect(result.value.interface.dns).toEqual(["10.200.200.1"])
  expect(result.value.interface.mtu).toBe(1420)
})

test("parse config - peer section", () => {
  const result = Config.parseConfig(sampleConfig)
  expect(result.ok).toBe(true)
  if (!result.ok) return

  expect(result.value.peers.length).toBe(1)
  expect(result.value.peers[0]!.publicKey.length).toBe(32)
  expect(result.value.peers[0]!.endpoint).toBe("my.server.com:51820")
  expect(result.value.peers[0]!.persistentKeepalive).toBe(25)
  expect(result.value.peers[0]!.allowedIPs).toEqual(["0.0.0.0/0", "::/0"])
})

test("parse config - socks5 section", () => {
  const result = Config.parseConfig(sampleConfig)
  expect(result.ok).toBe(true)
  if (!result.ok) return

  const socks = result.value.routines.find((r) => r.type === "socks5")
  expect(socks).toBeDefined()
  if (socks?.type === "socks5") {
    expect(socks.bindAddress).toBe("127.0.0.1:25344")
    expect(socks.username).toBe("testuser")
    expect(socks.password).toBe("testpass")
  }
})

test("parse config - http section", () => {
  const result = Config.parseConfig(sampleConfig)
  expect(result.ok).toBe(true)
  if (!result.ok) return

  const http = result.value.routines.find((r) => r.type === "http")
  expect(http).toBeDefined()
  if (http?.type === "http") {
    expect(http.bindAddress).toBe("127.0.0.1:25345")
  }
})

test("parse config - tcp client tunnel", () => {
  const result = Config.parseConfig(sampleConfig)
  expect(result.ok).toBe(true)
  if (!result.ok) return

  const tcp = result.value.routines.find((r) => r.type === "tcpClient")
  expect(tcp).toBeDefined()
  if (tcp?.type === "tcpClient") {
    expect(tcp.bindAddress).toBe("127.0.0.1:25565")
    expect(tcp.target).toBe("remote.host:25565")
  }
})

test("parse config - udp proxy tunnel", () => {
  const result = Config.parseConfig(sampleConfig)
  expect(result.ok).toBe(true)
  if (!result.ok) return

  const udp = result.value.routines.find((r) => r.type === "udp")
  expect(udp).toBeDefined()
  if (udp?.type === "udp") {
    expect(udp.bindAddress).toBe("127.0.0.1:53")
    expect(udp.target).toBe("1.1.1.1:53")
    expect(udp.inactivityTimeout).toBe(30)
  }
})

test("parse config - default resolve strategy", () => {
  const result = Config.parseConfig(sampleConfig)
  expect(result.ok).toBe(true)
  if (!result.ok) return

  expect(result.value.resolve.resolveStrategy).toBe("auto")
})

test("missing interface section returns error", () => {
  const result = Config.parseConfig(
    "[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
  )
  expect(result.ok).toBe(false)
  if (result.ok) return

  expect(result.error.message).toBe("exactly one [Interface] section required")
})

test("missing peer section returns error", () => {
  const result = Config.parseConfig(
    "[Interface]\nPrivateKey = YNqHbfBQKaGvzefJtfkbMuig9bLFPiuo1PKKTq1HE0g=\nAddress = 10.0.0.1\n",
  )
  expect(result.ok).toBe(false)
  if (result.ok) return

  expect(result.error.message).toBe("at least one [Peer] section required")
})

test("multiple peers", () => {
  const result = Config.parseConfig(`
[Interface]
PrivateKey = YNqHbfBQKaGvzefJtfkbMuig9bLFPiuo1PKKTq1HE0g=
Address = 10.0.0.1

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
Endpoint = server1:51820

[Peer]
PublicKey = BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=
Endpoint = server2:51820
`)
  expect(result.ok).toBe(true)
  if (!result.ok) return

  expect(result.value.peers.length).toBe(2)
})

test("unknown section returns error", () => {
  const result = Config.parseConfig(`
[Interface]
PrivateKey = YNqHbfBQKaGvzefJtfkbMuig9bLFPiuo1PKKTq1HE0g=

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=

[Sock5]
BindAddress = 127.0.0.1:1080
`)
  expect(result.ok).toBe(false)
  if (result.ok) return

  expect(result.error.message).toContain("unknown config section")
})

test("unknown key returns error", () => {
  const result = Config.parseConfig(`
[Interface]
PrivateKey = YNqHbfBQKaGvzefJtfkbMuig9bLFPiuo1PKKTq1HE0g=
Address = 10.0.0.1
Typo = nope

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
`)
  expect(result.ok).toBe(false)
  if (result.ok) return

  expect(result.error.message).toContain("unknown config key")
})

test("unsupported wg-quick key returns unknown key error", () => {
  const result = Config.parseConfig(`
[Interface]
PrivateKey = YNqHbfBQKaGvzefJtfkbMuig9bLFPiuo1PKKTq1HE0g=
Address = 10.0.0.1
PostUp = ip route add 1.1.1.1

[Peer]
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
`)
  expect(result.ok).toBe(false)
  if (result.ok) return

  expect(result.error.message).toContain("unknown config key")
})
