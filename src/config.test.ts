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
  const config = Config.parseConfig(sampleConfig)
  expect(config.interface.privateKey.length).toBe(32)
  expect(config.interface.address).toEqual(["10.200.200.2"])
  expect(config.interface.dns).toEqual(["10.200.200.1"])
  expect(config.interface.mtu).toBe(1420)
})

test("parse config - peer section", () => {
  const config = Config.parseConfig(sampleConfig)
  expect(config.peers.length).toBe(1)
  expect(config.peers[0]!.publicKey.length).toBe(32)
  expect(config.peers[0]!.endpoint).toBe("my.server.com:51820")
  expect(config.peers[0]!.persistentKeepalive).toBe(25)
  expect(config.peers[0]!.allowedIPs).toEqual(["0.0.0.0/0", "::/0"])
})

test("parse config - socks5 section", () => {
  const config = Config.parseConfig(sampleConfig)
  const socks = config.routines.find((r) => r.type === "socks5")
  expect(socks).toBeDefined()
  if (socks?.type === "socks5") {
    expect(socks.bindAddress).toBe("127.0.0.1:25344")
    expect(socks.username).toBe("testuser")
    expect(socks.password).toBe("testpass")
  }
})

test("parse config - http section", () => {
  const config = Config.parseConfig(sampleConfig)
  const http = config.routines.find((r) => r.type === "http")
  expect(http).toBeDefined()
  if (http?.type === "http") {
    expect(http.bindAddress).toBe("127.0.0.1:25345")
  }
})

test("parse config - tcp client tunnel", () => {
  const config = Config.parseConfig(sampleConfig)
  const tcp = config.routines.find((r) => r.type === "tcpClient")
  expect(tcp).toBeDefined()
  if (tcp?.type === "tcpClient") {
    expect(tcp.bindAddress).toBe("127.0.0.1:25565")
    expect(tcp.target).toBe("remote.host:25565")
  }
})

test("parse config - udp proxy tunnel", () => {
  const config = Config.parseConfig(sampleConfig)
  const udp = config.routines.find((r) => r.type === "udp")
  expect(udp).toBeDefined()
  if (udp?.type === "udp") {
    expect(udp.bindAddress).toBe("127.0.0.1:53")
    expect(udp.target).toBe("1.1.1.1:53")
    expect(udp.inactivityTimeout).toBe(30)
  }
})

test("parse config - default resolve strategy", () => {
  const config = Config.parseConfig(sampleConfig)
  expect(config.resolve.resolveStrategy).toBe("auto")
})

test("missing interface section throws", () => {
  expect(() =>
    Config.parseConfig("[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"),
  ).toThrow()
})

test("missing peer section throws", () => {
  expect(() =>
    Config.parseConfig(
      "[Interface]\nPrivateKey = YNqHbfBQKaGvzefJtfkbMuig9bLFPiuo1PKKTq1HE0g=\nAddress = 10.0.0.1\n",
    ),
  ).toThrow()
})

test("multiple peers", () => {
  const config = Config.parseConfig(`
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
  expect(config.peers.length).toBe(2)
})
