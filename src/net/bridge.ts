/**
 * Bridge between a Node Socket and a Web Streams
 */

import type * as NNet from "node:net"

export interface StreamPair {
  readable: ReadableStream<Uint8Array>
  writable: WritableStream<Uint8Array>
  close(): void
}

/**
 * Pipe data bidirectionally between a Node Socket and a web stream pair.
 * Handles cleanup when either side closes or errors.
 */
export function bridge(socket: NNet.Socket, remote: StreamPair): void {
  let closed = false

  const cleanup = () => {
    if (closed) return
    closed = true
    socket.destroy()
    remote.close()
  }

  // Socket → remote.writable
  const writer = remote.writable.getWriter()
  socket.on("data", (chunk: Buffer) => {
    writer.write(new Uint8Array(chunk)).catch(() => cleanup())
  })
  socket.on("end", () => {
    writer.close().catch(() => { })
  })
  socket.on("error", () => cleanup())
  socket.on("close", () => cleanup())

  // remote.readable → socket
  const reader = remote.readable.getReader()
    ; (async () => {
      try {
        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          if (!socket.writable) break
          socket.write(value)
        }
        if (socket.writable) socket.end()
      } catch {
        // Stream errored — cleanup
      }
      cleanup()
    })()
}
