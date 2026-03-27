/**
 * HTTP/HTTPS proxy server implementation.
 * Supports CONNECT (tunneling) and GET methods.
 * Pure JS, no external dependencies.
 */

import * as NNet from "node:net"
import * as NTls from "node:tls"
import * as NFs from "node:fs"
import * as NCrypto from "node:crypto"
import type { StreamPair } from "../net/Bridge.ts"
import { bridge } from "../net/Bridge.ts"

export interface HttpProxyOptions {
  bindAddress: string
  username?: string
  password?: string
  certFile?: string
  keyFile?: string
  dial: (host: string, port: number) => Promise<StreamPair>
}

function constantTimeCompare(a: string, b: string): boolean {
  const aBuf = Buffer.from(a)
  const bBuf = Buffer.from(b)
  if (aBuf.length !== bBuf.length) return false
  return NCrypto.timingSafeEqual(aBuf, bBuf)
}

export function startHttpProxy(options: HttpProxyOptions): Promise<void> {
  const { bindAddress, username, password, certFile, keyFile, dial } = options
  const requireAuth = !!username || !!password

  return new Promise((resolve, reject) => {
    const handler = (client: NNet.Socket) => {
      handleConnection(client).catch(() => client.destroy())
    }

    let server: NNet.Server
    if (certFile && keyFile) {
      const cert = NFs.readFileSync(certFile)
      const key = NFs.readFileSync(keyFile)
      server = NTls.createServer({ cert, key }, handler) as unknown as NNet.Server
    } else {
      server = NNet.createServer(handler)
    }

    async function handleConnection(client: NNet.Socket) {
      // Read the HTTP request line and headers
      const headerData = await readHttpHeaders(client)
      if (!headerData) {
        client.destroy()
        return
      }

      const { method, host, headers, rawFirstLine } = headerData

      // Authenticate
      if (requireAuth) {
        const authHeader = headers["proxy-authorization"] || ""
        const encoded = authHeader.replace(/^Basic\s+/i, "")
        let decoded: string
        try {
          decoded = Buffer.from(encoded, "base64").toString()
        } catch {
          sendResponse(client, 407, "Proxy Authentication Required", {
            "Proxy-Authenticate": 'Basic realm="Proxy"',
          })
          client.destroy()
          return
        }

        const [u, p] = decoded.split(":", 2)
        const validUser = constantTimeCompare(u ?? "", username ?? "")
        const validPass = constantTimeCompare(p ?? "", password ?? "")
        if (!validUser || !validPass) {
          sendResponse(client, 407, "Proxy Authentication Required", {
            "Proxy-Authenticate": 'Basic realm="Proxy"',
          })
          client.destroy()
          return
        }
      }

      if (method === "CONNECT") {
        await handleConnect(client, host)
      } else if (
        method === "GET" ||
        method === "POST" ||
        method === "PUT" ||
        method === "DELETE" ||
        method === "HEAD" ||
        method === "OPTIONS" ||
        method === "PATCH"
      ) {
        await handleHttp(client, host, rawFirstLine, headers)
      } else {
        sendResponse(client, 405, "Method Not Allowed")
        client.destroy()
      }
    }

    async function handleConnect(client: NNet.Socket, hostPort: string) {
      const { host, port } = parseHostPort(hostPort, 443)

      let remote: StreamPair
      try {
        remote = await dial(host, port)
      } catch {
        sendResponse(client, 502, "Bad Gateway")
        client.destroy()
        return
      }

      client.write("HTTP/1.1 200 Connection established\r\n\r\n")

      bridge(client, remote)
    }

    async function handleHttp(
      client: NNet.Socket,
      hostPort: string,
      firstLine: string,
      headers: Record<string, string>,
    ) {
      const { host, port } = parseHostPort(hostPort, 80)

      let remote: StreamPair
      try {
        remote = await dial(host, port)
      } catch {
        sendResponse(client, 502, "Bad Gateway")
        client.destroy()
        return
      }

      // Forward the original request via the writable stream
      let reqStr = firstLine + "\r\n"
      for (const [k, v] of Object.entries(headers)) {
        if (k.toLowerCase() === "proxy-authorization") continue
        if (k.toLowerCase() === "proxy-connection") continue
        reqStr += `${k}: ${v}\r\n`
      }
      reqStr += "\r\n"

      const writer = remote.writable.getWriter()
      await writer.write(new TextEncoder().encode(reqStr))
      writer.releaseLock()

      bridge(client, remote)
    }

    function parseHostPort(hp: string, defaultPort: number): { host: string; port: number } {
      if (hp.includes(":")) {
        const idx = hp.lastIndexOf(":")
        return { host: hp.slice(0, idx), port: parseInt(hp.slice(idx + 1), 10) || defaultPort }
      }
      return { host: hp, port: defaultPort }
    }

    function sendResponse(
      client: NNet.Socket,
      code: number,
      status: string,
      headers?: Record<string, string>,
    ) {
      let resp = `HTTP/1.1 ${code} ${status}\r\n`
      if (headers) {
        for (const [k, v] of Object.entries(headers)) {
          resp += `${k}: ${v}\r\n`
        }
      }
      resp += `Content-Length: 0\r\n\r\n`
      client.write(resp)
    }

    const [host, portStr] = bindAddress.split(":")
    server.listen(parseInt(portStr!, 10), host, () => {
      console.log(`HTTP proxy listening on ${bindAddress}`)
      resolve()
    })
    server.on("error", reject)
  })
}

interface HttpHeaderResult {
  method: string
  host: string
  path: string
  headers: Record<string, string>
  rawFirstLine: string
}

function readHttpHeaders(socket: NNet.Socket): Promise<HttpHeaderResult | null> {
  return new Promise((resolve) => {
    let buf = ""

    const onData = (data: Buffer) => {
      buf += data.toString()
      const headerEnd = buf.indexOf("\r\n\r\n")
      if (headerEnd !== -1) {
        socket.removeListener("data", onData)
        socket.removeListener("error", onError)
        socket.removeListener("close", onClose)

        const headerStr = buf.slice(0, headerEnd)
        const remaining = buf.slice(headerEnd + 4)
        if (remaining.length > 0) {
          socket.unshift(Buffer.from(remaining))
        }

        const lines = headerStr.split("\r\n")
        const firstLine = lines[0]!
        const parts = firstLine.split(" ")
        const method = parts[0]!.toUpperCase()

        const headers: Record<string, string> = {}
        for (let i = 1; i < lines.length; i++) {
          const colonIdx = lines[i]!.indexOf(":")
          if (colonIdx === -1) continue
          const key = lines[i]!.slice(0, colonIdx).trim()
          const value = lines[i]!.slice(colonIdx + 1).trim()
          headers[key.toLowerCase()] = value
        }

        // Extract host
        let host = headers["host"] || ""
        if (method === "CONNECT") {
          host = parts[1] || host
        } else {
          try {
            const url = new URL(parts[1]!, `http://${host}`)
            host = url.host || host
          } catch {
            // keep host from header
          }
        }

        resolve({ method, host, path: parts[1] || "/", headers, rawFirstLine: firstLine })
      }
    }

    const onError = () => {
      socket.removeListener("data", onData)
      socket.removeListener("close", onClose)
      resolve(null)
    }

    const onClose = () => {
      socket.removeListener("data", onData)
      socket.removeListener("error", onError)
      resolve(null)
    }

    socket.on("data", onData)
    socket.on("error", onError)
    socket.on("close", onClose)
  })
}
