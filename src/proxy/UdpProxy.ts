/**
 * UDP proxy with per-client session management.
 * Direct port from wireproxy/udp_proxy.go.
 */

import { createSocket, Socket as UDPSocket } from "dgram"

export interface UDPProxyOptions {
  bindAddress: string
  target: string
  inactivityTimeout: number // seconds, 0 = never timeout
  dial: (target: string) => UDPSocket
}

interface UDPSession {
  remoteSocket: UDPSocket
  lastActive: number
  closed: boolean
}

export function startUDPProxy(options: UDPProxyOptions): Promise<void> {
  const { bindAddress, target, inactivityTimeout, dial } = options
  const sessions = new Map<string, UDPSession>()
  const inactivityMs = inactivityTimeout * 1000

  return new Promise((resolve, reject) => {
    const [host, portStr] = bindAddress.split(":")
    const port = parseInt(portStr!, 10)

    const listener = createSocket("udp4")

    function closeSession(key: string, sess: UDPSession) {
      if (sess.closed) return
      sess.closed = true
      sess.remoteSocket.close()
      sessions.delete(key)
    }

    // Periodic cleanup of inactive sessions
    if (inactivityTimeout > 0) {
      setInterval(() => {
        const now = Date.now()
        for (const [key, sess] of sessions) {
          if (now - sess.lastActive >= inactivityMs) {
            console.log(`UDP Proxy: closing inactive session ${key}`)
            closeSession(key, sess)
          }
        }
      }, 10_000)
    }

    listener.on("message", (msg, rinfo) => {
      const srcKey = `${rinfo.address}:${rinfo.port}`

      let sess = sessions.get(srcKey)
      if (!sess) {
        // Create new session
        const remoteSocket = dial(target)

        sess = {
          remoteSocket,
          lastActive: Date.now(),
          closed: false,
        }
        sessions.set(srcKey, sess)

        // Handle remote -> local
        remoteSocket.on("message", (remoteMsg) => {
          const s = sessions.get(srcKey)
          if (!s || s.closed) return
          s.lastActive = Date.now()
          listener.send(remoteMsg, rinfo.port, rinfo.address)
        })

        remoteSocket.on("error", (err) => {
          console.error(`UDP Proxy: remote error for ${srcKey}: ${err.message}`)
          const s = sessions.get(srcKey)
          if (s) closeSession(srcKey, s)
        })
      }

      sess.lastActive = Date.now()

      // Forward to remote
      const [targetHost, targetPortStr] = target.split(":")
      const targetPort = parseInt(targetPortStr!, 10)
      sess.remoteSocket.send(msg, targetPort, targetHost)
    })

    listener.bind(port, host, () => {
      console.log(`UDP Proxy: ${bindAddress} -> ${target}`)
      resolve()
    })
    listener.on("error", reject)
  })
}
