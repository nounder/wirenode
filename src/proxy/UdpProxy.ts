/**
 * UDP proxy with per-client session management.
 * Direct port from wireproxy/udp_proxy.go.
 */

import * as NDgram from "node:dgram"

export interface UdpSocket {
  send(data: Uint8Array): void
  close(): void
  on(event: "message", listener: (msg: Uint8Array) => void): this
  on(event: "error", listener: (err: Error) => void): this
}

export interface UdpProxyOptions {
  bindAddress: string
  target: string
  inactivityTimeout: number // seconds, 0 = never timeout
  dial: (target: string) => UdpSocket | Promise<UdpSocket>
}

interface UdpSession {
  remoteSocket: UdpSocket | null
  pending: Promise<UdpSocket> | null
  lastActive: number
  closed: boolean
}

export function startUdpProxy(options: UdpProxyOptions): Promise<void> {
  const { bindAddress, target, inactivityTimeout, dial } = options
  const sessions = new Map<string, UdpSession>()
  const inactivityMs = inactivityTimeout * 1000

  return new Promise((resolve, reject) => {
    const [host, portStr] = bindAddress.split(":")
    const port = parseInt(portStr!, 10)

    const listener = NDgram.createSocket("udp4")

    function closeSession(key: string, session: UdpSession) {
      if (session.closed) return
      session.closed = true
      session.remoteSocket?.close()
      sessions.delete(key)
    }

    // Periodic cleanup of inactive sessions
    if (inactivityTimeout > 0) {
      setInterval(() => {
        const now = Date.now()
        for (const [key, session] of sessions) {
          if (now - session.lastActive >= inactivityMs) {
            console.log(`UDP Proxy: closing inactive session ${key}`)
            closeSession(key, session)
          }
        }
      }, 10_000)
    }

    listener.on("message", (msg, rinfo) => {
      void handleMessage(msg, rinfo)
    })

    async function handleMessage(msg: Buffer, rinfo: NDgram.RemoteInfo) {
      const srcKey = `${rinfo.address}:${rinfo.port}`

      let session = sessions.get(srcKey)
      if (!session) {
        session = {
          remoteSocket: null,
          pending: null,
          lastActive: Date.now(),
          closed: false,
        }
        sessions.set(srcKey, session)

        const newSession = session
        newSession.pending = Promise.resolve(dial(target))
          .then((remoteSocket) => {
            if (newSession.closed) {
              remoteSocket.close()
              return remoteSocket
            }

            newSession.remoteSocket = remoteSocket
            newSession.pending = null

            // Handle remote -> local
            remoteSocket.on("message", (remoteMsg) => {
              const current = sessions.get(srcKey)
              if (!current || current.closed) return
              current.lastActive = Date.now()
              listener.send(remoteMsg, rinfo.port, rinfo.address)
            })

            remoteSocket.on("error", (err) => {
              console.error(`UDP Proxy: remote error for ${srcKey}: ${err.message}`)
              const current = sessions.get(srcKey)
              if (current) closeSession(srcKey, current)
            })

            return remoteSocket
          })
          .catch((err: unknown) => {
            const message = err instanceof Error ? err.message : String(err)
            console.error(`UDP Proxy: dial error for ${srcKey}: ${message}`)
            const current = sessions.get(srcKey)
            if (current) closeSession(srcKey, current)
            throw err
          })
      }

      session.lastActive = Date.now()

      try {
        const remoteSocket = session.remoteSocket ?? (await session.pending)
        if (!remoteSocket || session.closed) return
        remoteSocket.send(new Uint8Array(msg))
      } catch {
        // Dial failure was already logged and the session was closed.
      }
    }

    listener.bind(port, host, () => {
      console.log(`UDP Proxy: ${bindAddress} -> ${target}`)
      resolve()
    })
    listener.on("error", reject)
  })
}
