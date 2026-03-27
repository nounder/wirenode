/**
 * SOCKS5 proxy server implementation (RFC 1928).
 * Pure JS, no external dependencies.
 */

import { createServer, Socket } from "net"
import { timingSafeEqual } from "crypto"
import type { StreamPair } from "../net/bridge.ts"
import { bridge } from "../net/bridge.ts"

export interface Socks5Options {
  bindAddress: string
  username?: string
  password?: string
  dial: (host: string, port: number) => Promise<StreamPair>
}

const SOCKS_VERSION = 0x05
const AUTH_NONE = 0x00
const AUTH_USERPASS = 0x02
const AUTH_NO_ACCEPTABLE = 0xff
const CMD_CONNECT = 0x01
const ATYP_IPV4 = 0x01
const ATYP_DOMAIN = 0x03
const ATYP_IPV6 = 0x04
const REP_SUCCESS = 0x00
const REP_HOST_UNREACHABLE = 0x04
const REP_COMMAND_NOT_SUPPORTED = 0x07
const REP_ADDR_TYPE_NOT_SUPPORTED = 0x08

function readExact(socket: Socket, n: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    let received = 0

    const onData = (data: Buffer) => {
      chunks.push(data)
      received += data.length
      if (received >= n) {
        socket.removeListener("data", onData)
        socket.removeListener("error", onError)
        socket.removeListener("close", onClose)
        const buf = Buffer.concat(chunks)
        if (buf.length > n) {
          socket.unshift(buf.subarray(n))
        }
        resolve(buf.subarray(0, n))
      }
    }

    const onError = (err: Error) => {
      socket.removeListener("data", onData)
      socket.removeListener("close", onClose)
      reject(err)
    }

    const onClose = () => {
      socket.removeListener("data", onData)
      socket.removeListener("error", onError)
      reject(new Error("connection closed"))
    }

    socket.on("data", onData)
    socket.on("error", onError)
    socket.on("close", onClose)
  })
}

function constantTimeCompare(a: string, b: string): boolean {
  const aBuf = Buffer.from(a)
  const bBuf = Buffer.from(b)
  if (aBuf.length !== bBuf.length) return false
  return timingSafeEqual(aBuf, bBuf)
}

export function startSocks5(options: Socks5Options): Promise<void> {
  const { bindAddress, username, password, dial } = options
  const requireAuth = !!username

  return new Promise((resolve, reject) => {
    const server = createServer(async (client) => {
      try {
        await handleClient(client)
      } catch {
        client.destroy()
      }
    })

    async function handleClient(client: Socket) {
      // Read greeting
      const greeting = await readExact(client, 2)
      if (greeting[0] !== SOCKS_VERSION) {
        client.destroy()
        return
      }

      const nMethods = greeting[1]!
      const methods = await readExact(client, nMethods)

      // Select auth method
      if (requireAuth) {
        if (!methods.includes(AUTH_USERPASS)) {
          client.write(Buffer.from([SOCKS_VERSION, AUTH_NO_ACCEPTABLE]))
          client.destroy()
          return
        }
        client.write(Buffer.from([SOCKS_VERSION, AUTH_USERPASS]))

        // Username/password auth (RFC 1929)
        const authVer = await readExact(client, 1)
        if (authVer[0] !== 0x01) {
          client.destroy()
          return
        }

        const ulenBuf = await readExact(client, 1)
        const uname = await readExact(client, ulenBuf[0]!)
        const plenBuf = await readExact(client, 1)
        const passwd = await readExact(client, plenBuf[0]!)

        const validUser = constantTimeCompare(uname.toString(), username!)
        const validPass = constantTimeCompare(passwd.toString(), password ?? "")

        if (!validUser || !validPass) {
          client.write(Buffer.from([0x01, 0x01])) // auth failure
          client.destroy()
          return
        }
        client.write(Buffer.from([0x01, 0x00])) // auth success
      } else {
        if (!methods.includes(AUTH_NONE)) {
          client.write(Buffer.from([SOCKS_VERSION, AUTH_NO_ACCEPTABLE]))
          client.destroy()
          return
        }
        client.write(Buffer.from([SOCKS_VERSION, AUTH_NONE]))
      }

      // Read request
      const reqHeader = await readExact(client, 4)
      if (reqHeader[0] !== SOCKS_VERSION) {
        client.destroy()
        return
      }

      const cmd = reqHeader[1]!
      // reqHeader[2] is reserved
      const atyp = reqHeader[3]!

      if (cmd !== CMD_CONNECT) {
        sendReply(client, REP_COMMAND_NOT_SUPPORTED, "0.0.0.0", 0)
        client.destroy()
        return
      }

      let host: string
      let port: number

      switch (atyp) {
        case ATYP_IPV4: {
          const addr = await readExact(client, 4)
          host = `${addr[0]}.${addr[1]}.${addr[2]}.${addr[3]}`
          const portBuf = await readExact(client, 2)
          port = portBuf.readUInt16BE(0)
          break
        }
        case ATYP_DOMAIN: {
          const lenBuf = await readExact(client, 1)
          const domain = await readExact(client, lenBuf[0]!)
          host = domain.toString()
          const portBuf = await readExact(client, 2)
          port = portBuf.readUInt16BE(0)
          break
        }
        case ATYP_IPV6: {
          const addr = await readExact(client, 16)
          const parts: string[] = []
          for (let i = 0; i < 16; i += 2) {
            parts.push(addr.readUInt16BE(i).toString(16))
          }
          host = parts.join(":")
          const portBuf = await readExact(client, 2)
          port = portBuf.readUInt16BE(0)
          break
        }
        default:
          sendReply(client, REP_ADDR_TYPE_NOT_SUPPORTED, "0.0.0.0", 0)
          client.destroy()
          return
      }

      // Connect through WireGuard tunnel
      let remote: StreamPair
      try {
        remote = await dial(host, port)
      } catch {
        sendReply(client, REP_HOST_UNREACHABLE, "0.0.0.0", 0)
        client.destroy()
        return
      }

      sendReply(client, REP_SUCCESS, "0.0.0.0", 0)

      // Bidirectional bridge: Node Socket ↔ web streams
      bridge(client, remote)
    }

    function sendReply(client: Socket, rep: number, bindAddr: string, bindPort: number) {
      const parts = bindAddr.split(".").map(Number)
      const reply = Buffer.alloc(10)
      reply[0] = SOCKS_VERSION
      reply[1] = rep
      reply[2] = 0x00 // reserved
      reply[3] = ATYP_IPV4
      reply[4] = parts[0]!
      reply[5] = parts[1]!
      reply[6] = parts[2]!
      reply[7] = parts[3]!
      reply.writeUInt16BE(bindPort, 8)
      client.write(reply)
    }

    const [host, portStr] = bindAddress.split(":")
    server.listen(parseInt(portStr!, 10), host, () => {
      console.log(`SOCKS5 proxy listening on ${bindAddress}`)
      resolve()
    })
    server.on("error", reject)
  })
}
