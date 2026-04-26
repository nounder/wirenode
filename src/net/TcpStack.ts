/**
 * Minimal userspace TCP/IP stack for outbound connections over WireGuard.
 *
 * Handles: IPv4 header construction/parsing, TCP 3-way handshake,
 * data transfer with sliding window, retransmission, and connection teardown.
 */
import * as NCrypto from "node:crypto"
import type * as Peer from "../wireguard/Peer.ts"
import type * as TypedEmitter from "../util/TypedEmitter.ts"
import * as IPv4 from "./IPv4.ts"

export interface PacketTransport {
  events: TypedEmitter.TypedEmitter<{ packet: [data: Uint8Array, peer: Peer.Peer] }>
  sendPacket(peer: Peer.Peer, data: Uint8Array): void
  getPeers(): Peer.Peer[]
}

const IP_PROTO_TCP = 6

// ─── TCP Protocol ───────────────────────────────────────────────────────────

const TCP_HEADER_LEN = 20
const TCP_FIN = 0x01
const TCP_SYN = 0x02
const TCP_RST = 0x04
const TCP_PSH = 0x08
const TCP_ACK = 0x10

function buildTCPSegment(
  srcPort: number,
  dstPort: number,
  seqNum: number,
  ackNum: number,
  flags: number,
  windowSize: number,
  payload: Uint8Array,
  srcIP: Uint8Array,
  dstIP: Uint8Array,
): Uint8Array {
  // TCP header with possible MSS option on SYN
  const hasMSS = (flags & TCP_SYN) !== 0
  const headerLen = hasMSS ? 24 : TCP_HEADER_LEN
  const segment = new Uint8Array(headerLen + payload.length)
  const view = new DataView(segment.buffer)

  view.setUint16(0, srcPort, false)
  view.setUint16(2, dstPort, false)
  view.setUint32(4, seqNum >>> 0, false)
  view.setUint32(8, ackNum >>> 0, false)
  segment[12] = (headerLen >> 2) << 4 // data offset
  segment[13] = flags
  view.setUint16(14, windowSize, false)
  // checksum at 16-17, filled below
  view.setUint16(18, 0, false) // urgent pointer

  // MSS option on SYN
  if (hasMSS) {
    segment[20] = 2 // kind: MSS
    segment[21] = 4 // length
    view.setUint16(22, 1360, false) // MSS value (conservative for WG)
  }

  // Copy payload
  segment.set(payload, headerLen)

  // TCP checksum with pseudo-header
  const cksum = tcpChecksum(srcIP, dstIP, segment)
  view.setUint16(16, cksum, false)

  return segment
}

function tcpChecksum(srcIP: Uint8Array, dstIP: Uint8Array, segment: Uint8Array): number {
  // Pseudo-header: srcIP(4) + dstIP(4) + zero(1) + protocol(1) + tcpLen(2) + TCP segment
  const pseudoLen = 12 + segment.length
  const pseudo = new Uint8Array(pseudoLen + (pseudoLen & 1)) // pad to even
  pseudo.set(srcIP, 0)
  pseudo.set(dstIP, 4)
  pseudo[8] = 0
  pseudo[9] = IP_PROTO_TCP
  const pView = new DataView(pseudo.buffer)
  pView.setUint16(10, segment.length, false)
  pseudo.set(segment, 12)

  return IPv4.checksum(pseudo)
}

interface TCPHeader {
  srcPort: number
  dstPort: number
  seqNum: number
  ackNum: number
  dataOffset: number // in bytes
  flags: number
  windowSize: number
  payload: Uint8Array
}

function parseTCPSegment(data: Uint8Array): TCPHeader | null {
  if (data.length < TCP_HEADER_LEN) return null
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)

  const srcPort = view.getUint16(0, false)
  const dstPort = view.getUint16(2, false)
  const seqNum = view.getUint32(4, false)
  const ackNum = view.getUint32(8, false)
  const dataOffset = ((data[12]! >> 4) & 0xf) * 4
  const flags = data[13]!
  const windowSize = view.getUint16(14, false)
  const payload = data.subarray(dataOffset)

  return { srcPort, dstPort, seqNum, ackNum, dataOffset, flags, windowSize, payload }
}

// ─── TCP Connection ─────────────────────────────────────────────────────────

const TcpState = {
  CLOSED: 0,
  SYN_SENT: 1,
  ESTABLISHED: 2,
  FIN_WAIT_1: 3,
  FIN_WAIT_2: 4,
  TIME_WAIT: 5,
  CLOSE_WAIT: 6,
  LAST_ACK: 7,
} as const
type TcpState = typeof TcpState[keyof typeof TcpState]

const RETRANSMIT_MS = 1000
const MAX_RETRANSMITS = 8
const RECV_WINDOW = 65535
const TIME_WAIT_MS = 2000
const MSS = 1360

interface UnackedSegment {
  seqNum: number
  data: Uint8Array // full IP packet to retransmit
  sentAt: number
  retransmits: number
  length: number // number of sequence numbers consumed (payload + SYN/FIN flags)
}

export class TcpConnection {
  #state: TcpState = TcpState.CLOSED
  #localPort: number
  #remotePort: number
  #localIP: Uint8Array
  #remoteIP: Uint8Array
  #peer: Peer.Peer
  #device: PacketTransport
  #ipId = 1

  #sendSeq: number // next sequence number to send
  #recvSeq: number = 0

  #unacked: UnackedSegment[] = []
  #retransmitTimer: ReturnType<typeof setInterval> | null = null
  #timeWaitTimer: ReturnType<typeof setTimeout> | null = null

  #destroyed = false

  // Web streams
  readonly readable: ReadableStream<Uint8Array>
  readonly writable: WritableStream<Uint8Array>
  #readableController: ReadableStreamDefaultController<Uint8Array> | null = null

  // Events (minimal, just connect/error/close for lifecycle)
  #connectResolve: (() => void) | null = null
  #connectReject: ((err: Error) => void) | null = null
  #onClose: (() => void) | null = null

  constructor(
    localIP: Uint8Array,
    remoteIP: Uint8Array,
    localPort: number,
    remotePort: number,
    peer: Peer.Peer,
    device: PacketTransport,
  ) {
    this.#localIP = localIP
    this.#remoteIP = remoteIP
    this.#localPort = localPort
    this.#remotePort = remotePort
    this.#peer = peer
    this.#device = device

    // Initial sequence number
    const rnd = NCrypto.randomBytes(4)
    this.#sendSeq = new DataView(rnd.buffer).getUint32(0, false)

    // Create ReadableStream
    this.readable = new ReadableStream<Uint8Array>({
      start: (controller) => {
        this.#readableController = controller
      },
      cancel: () => {
        this.close()
      },
    })

    // Create WritableStream
    this.writable = new WritableStream<Uint8Array>({
      write: (chunk) => {
        this.#writeData(chunk)
      },
      close: () => {
        if (this.#state === TcpState.ESTABLISHED) {
          this.#sendFIN()
          this.#state = TcpState.FIN_WAIT_1
        }
      },
      abort: () => {
        this.close()
      },
    })
  }

  /** Returns a promise that resolves when TCP handshake completes */
  connected(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      this.#connectResolve = resolve
      this.#connectReject = reject
    })
  }

  /** Register a callback for when the connection is fully closed */
  onClosed(cb: () => void): void {
    this.#onClose = cb
  }

  /** Initiate TCP handshake (SYN) */
  connect_(): void {
    this.#state = TcpState.SYN_SENT
    this.#sendTCP(TCP_SYN, new Uint8Array(0))
    this.#sendSeq = (this.#sendSeq + 1) >>> 0 // SYN consumes one sequence number
    this.#startRetransmitTimer()
  }

  /** Called by TcpStack when an IP packet arrives for this connection */
  handlePacket(tcpHeader: TCPHeader): void {
    if (this.#destroyed) return

    switch (this.#state) {
      case TcpState.SYN_SENT:
        this.#handleSynSent(tcpHeader)
        break
      case TcpState.ESTABLISHED:
        this.#handleEstablished(tcpHeader)
        break
      case TcpState.FIN_WAIT_1:
        this.#handleFinWait1(tcpHeader)
        break
      case TcpState.FIN_WAIT_2:
        this.#handleFinWait2(tcpHeader)
        break
      case TcpState.CLOSE_WAIT:
        this.#handleCloseWait(tcpHeader)
        break
      case TcpState.LAST_ACK:
        this.#handleLastAck(tcpHeader)
        break
      case TcpState.TIME_WAIT:
        if (tcpHeader.flags & TCP_FIN) {
          this.#sendACK()
        }
        break
    }
  }

  /** Forcefully close the connection */
  close(): void {
    if (this.#destroyed) return
    this.#destroyed = true
    if (this.#state === TcpState.ESTABLISHED || this.#state === TcpState.CLOSE_WAIT) {
      this.#sendRST()
    }
    this.#cleanup()
  }

  #handleSynSent(tcp: TCPHeader): void {
    if (tcp.flags & TCP_RST) {
      this.#emitError("connection refused")
      return
    }

    if ((tcp.flags & (TCP_SYN | TCP_ACK)) === (TCP_SYN | TCP_ACK)) {
      this.#recvSeq = (tcp.seqNum + 1) >>> 0
      this.#ackReceived(tcp.ackNum)
      this.#state = TcpState.ESTABLISHED
      this.#sendACK()
      this.#connectResolve?.()
      this.#connectResolve = null
      this.#connectReject = null
    }
  }

  #handleEstablished(tcp: TCPHeader): void {
    if (tcp.flags & TCP_RST) {
      this.#emitError("connection reset")
      return
    }

    if (tcp.flags & TCP_ACK) {
      this.#ackReceived(tcp.ackNum)
    }

    // Process incoming data
    if (tcp.payload.length > 0) {
      if (tcp.seqNum === this.#recvSeq) {
        this.#recvSeq = (this.#recvSeq + tcp.payload.length) >>> 0
        this.#readableController?.enqueue(new Uint8Array(tcp.payload))
        this.#sendACK()
      } else if (seqAfter(tcp.seqNum, this.#recvSeq)) {
        this.#sendACK()
      }
    }

    // Process FIN
    if (tcp.flags & TCP_FIN) {
      this.#recvSeq = (this.#recvSeq + 1) >>> 0
      this.#sendACK()
      try { this.#readableController?.close() } catch { }
      this.#readableController = null
      this.#state = TcpState.CLOSE_WAIT
      // Immediately send our FIN
      this.#sendFIN()
      this.#state = TcpState.LAST_ACK
    }
  }

  #handleFinWait1(tcp: TCPHeader): void {
    if (tcp.flags & TCP_RST) {
      this.#cleanup()
      return
    }

    if (tcp.flags & TCP_ACK) {
      this.#ackReceived(tcp.ackNum)
    }

    if (tcp.payload.length > 0 && tcp.seqNum === this.#recvSeq) {
      this.#recvSeq = (this.#recvSeq + tcp.payload.length) >>> 0
      this.#readableController?.enqueue(new Uint8Array(tcp.payload))
    }

    if (tcp.flags & TCP_FIN) {
      this.#recvSeq = (this.#recvSeq + 1) >>> 0
      this.#sendACK()

      if (this.#unacked.length === 0) {
        this.#enterTimeWait()
      } else {
        this.#state = TcpState.TIME_WAIT
        this.#enterTimeWait()
      }
      try { this.#readableController?.close() } catch { }
      this.#readableController = null
    } else if (this.#unacked.length === 0) {
      this.#state = TcpState.FIN_WAIT_2
    }
  }

  #handleFinWait2(tcp: TCPHeader): void {
    if (tcp.flags & TCP_RST) {
      this.#cleanup()
      return
    }

    if (tcp.payload.length > 0 && tcp.seqNum === this.#recvSeq) {
      this.#recvSeq = (this.#recvSeq + tcp.payload.length) >>> 0
      this.#readableController?.enqueue(new Uint8Array(tcp.payload))
      this.#sendACK()
    }

    if (tcp.flags & TCP_FIN) {
      this.#recvSeq = (this.#recvSeq + 1) >>> 0
      this.#sendACK()
      try { this.#readableController?.close() } catch { }
      this.#readableController = null
      this.#enterTimeWait()
    }
  }

  #handleCloseWait(tcp: TCPHeader): void {
    if (tcp.flags & TCP_ACK) {
      this.#ackReceived(tcp.ackNum)
    }
  }

  #handleLastAck(tcp: TCPHeader): void {
    if (tcp.flags & TCP_ACK) {
      this.#ackReceived(tcp.ackNum)
      if (this.#unacked.length === 0) {
        this.#cleanup()
      }
    }
  }

  // ─── Writing ──────────────────────────────────────────────────────────────

  #writeData(chunk: Uint8Array): void {
    if (this.#state !== TcpState.ESTABLISHED || this.#destroyed) return

    let offset = 0
    while (offset < chunk.length) {
      const end = Math.min(offset + MSS, chunk.length)
      const data = chunk.subarray(offset, end)
      this.#sendTCP(TCP_ACK | TCP_PSH, data)
      this.#sendSeq = (this.#sendSeq + data.length) >>> 0
      offset = end
    }
  }

  // ─── Sending helpers ────────────────────────────────────────────────────

  #sendTCP(flags: number, payload: Uint8Array): void {
    const segment = buildTCPSegment(
      this.#localPort,
      this.#remotePort,
      this.#sendSeq,
      this.#recvSeq,
      flags,
      RECV_WINDOW,
      payload,
      this.#localIP,
      this.#remoteIP,
    )

    const ipPacket = IPv4.buildPacket(this.#localIP, this.#remoteIP, IP_PROTO_TCP, segment, this.#ipId++)
    if (this.#ipId > 0xffff) this.#ipId = 1

    const seqLen = payload.length + ((flags & TCP_SYN) ? 1 : 0) + ((flags & TCP_FIN) ? 1 : 0)
    if (seqLen > 0) {
      this.#unacked.push({
        seqNum: this.#sendSeq,
        data: ipPacket,
        sentAt: Date.now(),
        retransmits: 0,
        length: seqLen,
      })
    }

    this.#device.sendPacket(this.#peer, ipPacket)
  }

  #sendACK(): void {
    const segment = buildTCPSegment(
      this.#localPort,
      this.#remotePort,
      this.#sendSeq,
      this.#recvSeq,
      TCP_ACK,
      RECV_WINDOW,
      new Uint8Array(0),
      this.#localIP,
      this.#remoteIP,
    )

    const ipPacket = IPv4.buildPacket(this.#localIP, this.#remoteIP, IP_PROTO_TCP, segment, this.#ipId++)
    if (this.#ipId > 0xffff) this.#ipId = 1
    this.#device.sendPacket(this.#peer, ipPacket)
  }

  #sendFIN(): void {
    this.#sendTCP(TCP_ACK | TCP_FIN, new Uint8Array(0))
    this.#sendSeq = (this.#sendSeq + 1) >>> 0
  }

  #sendRST(): void {
    const segment = buildTCPSegment(
      this.#localPort,
      this.#remotePort,
      this.#sendSeq,
      this.#recvSeq,
      TCP_RST | TCP_ACK,
      0,
      new Uint8Array(0),
      this.#localIP,
      this.#remoteIP,
    )

    const ipPacket = IPv4.buildPacket(this.#localIP, this.#remoteIP, IP_PROTO_TCP, segment, this.#ipId++)
    this.#device.sendPacket(this.#peer, ipPacket)
  }

  // ─── Retransmission ─────────────────────────────────────────────────────

  #startRetransmitTimer(): void {
    if (this.#retransmitTimer) return
    this.#retransmitTimer = setInterval(() => this.#retransmit(), RETRANSMIT_MS)
  }

  #retransmit(): void {
    const now = Date.now()
    for (let i = this.#unacked.length - 1; i >= 0; i--) {
      const seg = this.#unacked[i]!
      if (now - seg.sentAt >= RETRANSMIT_MS) {
        if (seg.retransmits >= MAX_RETRANSMITS) {
          this.#emitError("connection timed out")
          return
        }
        seg.retransmits++
        seg.sentAt = now
        this.#device.sendPacket(this.#peer, seg.data)
      }
    }
  }

  #ackReceived(ackNum: number): void {
    this.#unacked = this.#unacked.filter((seg) => {
      const segEnd = (seg.seqNum + seg.length) >>> 0
      return seqAfter(segEnd, ackNum)
    })

    if (this.#unacked.length === 0 && this.#retransmitTimer) {
      clearInterval(this.#retransmitTimer)
      this.#retransmitTimer = null
    } else if (this.#unacked.length > 0 && !this.#retransmitTimer) {
      this.#startRetransmitTimer()
    }
  }

  // ─── Cleanup ────────────────────────────────────────────────────────────

  #enterTimeWait(): void {
    this.#state = TcpState.TIME_WAIT
    this.#timeWaitTimer = setTimeout(() => {
      this.#cleanup()
    }, TIME_WAIT_MS)
  }

  #cleanup(): void {
    this.#state = TcpState.CLOSED
    if (this.#retransmitTimer) {
      clearInterval(this.#retransmitTimer)
      this.#retransmitTimer = null
    }
    if (this.#timeWaitTimer) {
      clearTimeout(this.#timeWaitTimer)
      this.#timeWaitTimer = null
    }
    this.#unacked = []
    try { this.#readableController?.close() } catch { }
    this.#readableController = null
    this.#onClose?.()
  }

  #emitError(msg: string): void {
    this.#state = TcpState.CLOSED
    const err = new Error(msg)
    this.#connectReject?.(err)
    this.#connectResolve = null
    this.#connectReject = null
    try { this.#readableController?.error(err) } catch { }
    this.#readableController = null
    this.#cleanup()
  }

  /** Connection key for lookup */
  get key(): string {
    return connectionKey(this.#localPort, this.#remotePort, this.#remoteIP)
  }
}

// ─── TCP Stack (manages all connections) ────────────────────────────────────

function connectionKey(localPort: number, remotePort: number, remoteIP: Uint8Array): string {
  return `${localPort}:${remoteIP[0]}.${remoteIP[1]}.${remoteIP[2]}.${remoteIP[3]}:${remotePort}`
}

/** Compare sequence numbers (handles wrapping) */
function seqAfter(a: number, b: number): boolean {
  return ((a - b) & 0xffffffff) > 0 && ((a - b) & 0xffffffff) < 0x80000000
}

/** Ephemeral port allocator — randomize start to avoid collisions across runs */
let nextEphemeralPort = 49152 + Math.floor(Math.random() * 8192)

function allocatePort(): number {
  const port = nextEphemeralPort++
  if (nextEphemeralPort > 65535) nextEphemeralPort = 49152
  return port
}

export class TcpStack {
  #device: PacketTransport
  #connections: Map<string, TcpConnection> = new Map()
  #localIP: Uint8Array

  constructor(device: PacketTransport, localIP: string) {
    this.#device = device
    this.#localIP = IPv4.parse(localIP)

    this.#device.events.on("packet", (data: Uint8Array, _peer: Peer.Peer) => {
      this.#handleIPPacket(data)
    })
  }

  /** Create a new outbound TCP connection through the WireGuard tunnel */
  connect(host: string, port: number, peer: Peer.Peer): TcpConnection {
    const remoteIP = IPv4.parse(host)
    const localPort = allocatePort()

    const conn = new TcpConnection(this.#localIP, remoteIP, localPort, port, peer, this.#device)

    const key = connectionKey(localPort, port, remoteIP)
    this.#connections.set(key, conn)

    conn.onClosed(() => {
      this.#connections.delete(key)
    })

    conn.connect_()
    return conn
  }

  #handleIPPacket(packet: Uint8Array): void {
    const ip = IPv4.parsePacket(packet)
    if (!ip) return
    if (ip.protocol !== IP_PROTO_TCP) return

    const tcp = parseTCPSegment(ip.payload)
    if (!tcp) return

    const key = connectionKey(tcp.dstPort, tcp.srcPort, ip.src)
    const conn = this.#connections.get(key)
    if (!conn) {
      if (!(tcp.flags & TCP_RST)) {
        this.#sendRST(ip, tcp)
      }
      return
    }

    conn.handlePacket(tcp)
  }

  #sendRST(ip: { src: Uint8Array; dst: Uint8Array }, tcp: TCPHeader): void {
    const ackNum = (tcp.flags & TCP_ACK) ? 0 : (tcp.seqNum + tcp.payload.length + ((tcp.flags & TCP_SYN) ? 1 : 0) + ((tcp.flags & TCP_FIN) ? 1 : 0)) >>> 0
    const seqNum = (tcp.flags & TCP_ACK) ? tcp.ackNum : 0
    const flags = TCP_RST | ((tcp.flags & TCP_ACK) ? 0 : TCP_ACK)

    const segment = buildTCPSegment(
      tcp.dstPort,
      tcp.srcPort,
      seqNum,
      ackNum,
      flags,
      0,
      new Uint8Array(0),
      ip.dst,
      ip.src,
    )

    const ipPacket = IPv4.buildPacket(ip.dst, ip.src, IP_PROTO_TCP, segment, 0)
    const peers = this.#device.getPeers()
    if (peers[0]) {
      this.#device.sendPacket(peers[0], ipPacket)
    }
  }

  destroy(): void {
    for (const conn of this.#connections.values()) {
      conn.close()
    }
    this.#connections.clear()
  }
}

export { parseTCPSegment }
