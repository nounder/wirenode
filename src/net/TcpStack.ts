/**
 * Minimal userspace TCP/IP stack for outbound connections over WireGuard.
 *
 * Handles: IPv4 header construction/parsing, TCP 3-way handshake,
 * data transfer with sliding window, retransmission, and connection teardown.
 *
 * This is intentionally minimal — just enough for outbound CONNECT-style proxying.
 */

import { Duplex } from "stream"
import { randomBytes } from "crypto"
import { EventEmitter } from "events"
import type { Device } from "../device/Device.ts"
import type { Peer } from "../device/Peer.ts"

// ─── IP Protocol ────────────────────────────────────────────────────────────

const IP_VERSION = 4
const IP_HEADER_LEN = 20
const IP_PROTO_TCP = 6
const IP_TTL = 64

function buildIPv4Header(
  src: Uint8Array, // 4 bytes
  dst: Uint8Array, // 4 bytes
  protocol: number,
  payload: Uint8Array,
  id: number,
): Uint8Array {
  const totalLength = IP_HEADER_LEN + payload.length
  const header = new Uint8Array(totalLength)
  const view = new DataView(header.buffer)

  header[0] = (IP_VERSION << 4) | (IP_HEADER_LEN >> 2) // version + IHL
  header[1] = 0 // DSCP + ECN
  view.setUint16(2, totalLength, false) // total length
  view.setUint16(4, id, false) // identification
  view.setUint16(6, 0x4000, false) // flags: Don't Fragment
  header[8] = IP_TTL
  header[9] = protocol
  // checksum at offset 10-11, filled below
  header.set(src, 12)
  header.set(dst, 16)

  // IP header checksum
  view.setUint16(10, 0, false)
  const cksum = ipChecksum(header.subarray(0, IP_HEADER_LEN))
  view.setUint16(10, cksum, false)

  // Copy payload
  header.set(payload, IP_HEADER_LEN)
  return header
}

function ipChecksum(data: Uint8Array): number {
  let sum = 0
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength)
  for (let i = 0; i < data.length - 1; i += 2) {
    sum += view.getUint16(i, false)
  }
  if (data.length & 1) {
    sum += data[data.length - 1]! << 8
  }
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16)
  }
  return (~sum) & 0xffff
}

function parseIPv4(packet: Uint8Array): {
  src: Uint8Array
  dst: Uint8Array
  protocol: number
  payload: Uint8Array
  totalLength: number
} | null {
  if (packet.length < IP_HEADER_LEN) return null
  const version = (packet[0]! >> 4) & 0xf
  if (version !== 4) return null

  const ihl = (packet[0]! & 0xf) * 4
  if (packet.length < ihl) return null

  const view = new DataView(packet.buffer, packet.byteOffset, packet.byteLength)
  const totalLength = view.getUint16(2, false)
  const protocol = packet[9]!
  const src = packet.slice(12, 16)
  const dst = packet.slice(16, 20)
  const payload = packet.slice(ihl, totalLength)

  return { src, dst, protocol, payload, totalLength }
}

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

  return ipChecksum(pseudo)
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

const enum TcpState {
  CLOSED,
  SYN_SENT,
  ESTABLISHED,
  FIN_WAIT_1,
  FIN_WAIT_2,
  TIME_WAIT,
  CLOSE_WAIT,
  LAST_ACK,
}

const RETRANSMIT_MS = 1000
const MAX_RETRANSMITS = 8
const RECV_WINDOW = 65535
const TIME_WAIT_MS = 2000

interface UnackedSegment {
  seqNum: number
  data: Uint8Array // full IP packet to retransmit
  sentAt: number
  retransmits: number
  length: number // number of sequence numbers consumed (payload + SYN/FIN flags)
}

export class TcpConnection extends Duplex {
  private state = TcpState.CLOSED
  private localPort: number
  private remotePort: number
  private localIP: Uint8Array
  private remoteIP: Uint8Array
  private peer: Peer
  private device: Device
  private ipId = 1

  private sendSeq: number // next sequence number to send
  private recvSeq: number = 0 // next expected sequence number from remote

  private unacked: UnackedSegment[] = []
  private retransmitTimer: ReturnType<typeof setInterval> | null = null
  private timeWaitTimer: ReturnType<typeof setTimeout> | null = null

  private destroyed_ = false

  constructor(
    localIP: Uint8Array,
    remoteIP: Uint8Array,
    localPort: number,
    remotePort: number,
    peer: Peer,
    device: Device,
  ) {
    super()
    this.localIP = localIP
    this.remoteIP = remoteIP
    this.localPort = localPort
    this.remotePort = remotePort
    this.peer = peer
    this.device = device

    // Initial sequence number
    const rnd = randomBytes(4)
    this.sendSeq = new DataView(rnd.buffer).getUint32(0, false)
  }

  /** Initiate TCP handshake (SYN) */
  connect_(): void {
    this.state = TcpState.SYN_SENT
    this.sendTCP(TCP_SYN, new Uint8Array(0))
    this.sendSeq = (this.sendSeq + 1) >>> 0 // SYN consumes one sequence number
    this.startRetransmitTimer()
  }

  /** Called by TcpStack when an IP packet arrives for this connection */
  handlePacket(tcpHeader: TCPHeader): void {
    if (this.destroyed_) return

    switch (this.state) {
      case TcpState.SYN_SENT:
        this.handleSynSent(tcpHeader)
        break
      case TcpState.ESTABLISHED:
        this.handleEstablished(tcpHeader)
        break
      case TcpState.FIN_WAIT_1:
        this.handleFinWait1(tcpHeader)
        break
      case TcpState.FIN_WAIT_2:
        this.handleFinWait2(tcpHeader)
        break
      case TcpState.CLOSE_WAIT:
        this.handleCloseWait(tcpHeader)
        break
      case TcpState.LAST_ACK:
        this.handleLastAck(tcpHeader)
        break
      case TcpState.TIME_WAIT:
        // Already waiting, just ACK
        if (tcpHeader.flags & TCP_FIN) {
          this.sendACK()
        }
        break
    }
  }

  private handleSynSent(tcp: TCPHeader): void {
    if (tcp.flags & TCP_RST) {
      this.emitError("connection refused")
      return
    }

    if ((tcp.flags & (TCP_SYN | TCP_ACK)) === (TCP_SYN | TCP_ACK)) {
      // SYN-ACK received
      this.recvSeq = (tcp.seqNum + 1) >>> 0
      this.ackReceived(tcp.ackNum)
      this.state = TcpState.ESTABLISHED
      this.sendACK()
      this.emit("connect")
    }
  }

  private handleEstablished(tcp: TCPHeader): void {
    if (tcp.flags & TCP_RST) {
      this.emitError("connection reset")
      return
    }

    // Process ACK
    if (tcp.flags & TCP_ACK) {
      this.ackReceived(tcp.ackNum)
    }

    // Process incoming data
    if (tcp.payload.length > 0) {
      if (tcp.seqNum === this.recvSeq) {
        this.recvSeq = (this.recvSeq + tcp.payload.length) >>> 0
        this.push(Buffer.from(tcp.payload))
        this.sendACK()
      } else if (seqAfter(tcp.seqNum, this.recvSeq)) {
        // Out of order — just ACK with our expected seq
        this.sendACK()
      }
      // else: duplicate, ignore
    }

    // Process FIN
    if (tcp.flags & TCP_FIN) {
      this.recvSeq = (this.recvSeq + 1) >>> 0
      this.sendACK()
      this.push(null) // signal EOF to reader
      this.state = TcpState.CLOSE_WAIT
      // We immediately send our FIN
      this.sendFIN()
      this.state = TcpState.LAST_ACK
    }
  }

  private handleFinWait1(tcp: TCPHeader): void {
    if (tcp.flags & TCP_RST) {
      this.cleanup()
      return
    }

    if (tcp.flags & TCP_ACK) {
      this.ackReceived(tcp.ackNum)
    }

    // Process any remaining data
    if (tcp.payload.length > 0 && tcp.seqNum === this.recvSeq) {
      this.recvSeq = (this.recvSeq + tcp.payload.length) >>> 0
      this.push(Buffer.from(tcp.payload))
    }

    if (tcp.flags & TCP_FIN) {
      this.recvSeq = (this.recvSeq + 1) >>> 0
      this.sendACK()

      // Check if our FIN was also ACKed
      if (this.unacked.length === 0) {
        // Both FINs exchanged
        this.enterTimeWait()
      } else {
        // Simultaneous close
        this.state = TcpState.TIME_WAIT
        this.enterTimeWait()
      }
      this.push(null)
    } else if (this.unacked.length === 0) {
      // Our FIN was ACKed
      this.state = TcpState.FIN_WAIT_2
    }
  }

  private handleFinWait2(tcp: TCPHeader): void {
    if (tcp.flags & TCP_RST) {
      this.cleanup()
      return
    }

    // Process remaining data
    if (tcp.payload.length > 0 && tcp.seqNum === this.recvSeq) {
      this.recvSeq = (this.recvSeq + tcp.payload.length) >>> 0
      this.push(Buffer.from(tcp.payload))
      this.sendACK()
    }

    if (tcp.flags & TCP_FIN) {
      this.recvSeq = (this.recvSeq + 1) >>> 0
      this.sendACK()
      this.push(null)
      this.enterTimeWait()
    }
  }

  private handleCloseWait(tcp: TCPHeader): void {
    if (tcp.flags & TCP_ACK) {
      this.ackReceived(tcp.ackNum)
    }
  }

  private handleLastAck(tcp: TCPHeader): void {
    if (tcp.flags & TCP_ACK) {
      this.ackReceived(tcp.ackNum)
      if (this.unacked.length === 0) {
        this.cleanup()
      }
    }
  }

  // ─── Duplex stream interface ────────────────────────────────────────────

  override _read(): void {
    // Data is pushed in handleEstablished
  }

  override _write(chunk: Buffer, _encoding: string, callback: (error?: Error | null) => void): void {
    if (this.state !== TcpState.ESTABLISHED || this.destroyed_) {
      callback(new Error("not connected"))
      return
    }

    // Split into MSS-sized chunks
    const mss = 1360
    let offset = 0
    while (offset < chunk.length) {
      const end = Math.min(offset + mss, chunk.length)
      const data = new Uint8Array(chunk.subarray(offset, end))
      this.sendTCP(TCP_ACK | TCP_PSH, data)
      this.sendSeq = (this.sendSeq + data.length) >>> 0
      offset = end
    }

    callback()
  }

  override _final(callback: (error?: Error | null) => void): void {
    if (this.state === TcpState.ESTABLISHED) {
      this.sendFIN()
      this.state = TcpState.FIN_WAIT_1
    }
    callback()
  }

  override _destroy(err: Error | null, callback: (error?: Error | null) => void): void {
    if (!this.destroyed_) {
      this.destroyed_ = true
      if (this.state === TcpState.ESTABLISHED || this.state === TcpState.CLOSE_WAIT) {
        this.sendRST()
      }
      this.cleanup()
    }
    callback(err)
  }

  // ─── Sending helpers ────────────────────────────────────────────────────

  private sendTCP(flags: number, payload: Uint8Array): void {
    const segment = buildTCPSegment(
      this.localPort,
      this.remotePort,
      this.sendSeq,
      this.recvSeq,
      flags,
      RECV_WINDOW,
      payload,
      this.localIP,
      this.remoteIP,
    )

    const ipPacket = buildIPv4Header(this.localIP, this.remoteIP, IP_PROTO_TCP, segment, this.ipId++)
    if (this.ipId > 0xffff) this.ipId = 1

    // Track unacked if it consumes sequence space
    const seqLen = payload.length + ((flags & TCP_SYN) ? 1 : 0) + ((flags & TCP_FIN) ? 1 : 0)
    if (seqLen > 0) {
      this.unacked.push({
        seqNum: this.sendSeq,
        data: ipPacket,
        sentAt: Date.now(),
        retransmits: 0,
        length: seqLen,
      })
    }

    this.device.sendPacket(this.peer, ipPacket)
  }

  private sendACK(): void {
    const segment = buildTCPSegment(
      this.localPort,
      this.remotePort,
      this.sendSeq,
      this.recvSeq,
      TCP_ACK,
      RECV_WINDOW,
      new Uint8Array(0),
      this.localIP,
      this.remoteIP,
    )

    const ipPacket = buildIPv4Header(this.localIP, this.remoteIP, IP_PROTO_TCP, segment, this.ipId++)
    if (this.ipId > 0xffff) this.ipId = 1
    this.device.sendPacket(this.peer, ipPacket)
  }

  private sendFIN(): void {
    this.sendTCP(TCP_ACK | TCP_FIN, new Uint8Array(0))
    this.sendSeq = (this.sendSeq + 1) >>> 0 // FIN consumes a sequence number
  }

  private sendRST(): void {
    const segment = buildTCPSegment(
      this.localPort,
      this.remotePort,
      this.sendSeq,
      this.recvSeq,
      TCP_RST | TCP_ACK,
      0,
      new Uint8Array(0),
      this.localIP,
      this.remoteIP,
    )

    const ipPacket = buildIPv4Header(this.localIP, this.remoteIP, IP_PROTO_TCP, segment, this.ipId++)
    this.device.sendPacket(this.peer, ipPacket)
  }

  // ─── Retransmission ─────────────────────────────────────────────────────

  private startRetransmitTimer(): void {
    if (this.retransmitTimer) return
    this.retransmitTimer = setInterval(() => this.retransmit(), RETRANSMIT_MS)
  }

  private retransmit(): void {
    const now = Date.now()
    for (let i = this.unacked.length - 1; i >= 0; i--) {
      const seg = this.unacked[i]!
      if (now - seg.sentAt >= RETRANSMIT_MS) {
        if (seg.retransmits >= MAX_RETRANSMITS) {
          this.emitError("connection timed out")
          return
        }
        seg.retransmits++
        seg.sentAt = now
        this.device.sendPacket(this.peer, seg.data)
      }
    }
  }

  private ackReceived(ackNum: number): void {
    // Remove all segments that have been fully acknowledged
    this.unacked = this.unacked.filter((seg) => {
      const segEnd = (seg.seqNum + seg.length) >>> 0
      return seqAfter(segEnd, ackNum)
    })

    if (this.unacked.length === 0 && this.retransmitTimer) {
      clearInterval(this.retransmitTimer)
      this.retransmitTimer = null
    } else if (this.unacked.length > 0 && !this.retransmitTimer) {
      this.startRetransmitTimer()
    }
  }

  // ─── Cleanup ────────────────────────────────────────────────────────────

  private enterTimeWait(): void {
    this.state = TcpState.TIME_WAIT
    this.timeWaitTimer = setTimeout(() => {
      this.cleanup()
    }, TIME_WAIT_MS)
  }

  private cleanup(): void {
    this.state = TcpState.CLOSED
    if (this.retransmitTimer) {
      clearInterval(this.retransmitTimer)
      this.retransmitTimer = null
    }
    if (this.timeWaitTimer) {
      clearTimeout(this.timeWaitTimer)
      this.timeWaitTimer = null
    }
    this.unacked = []
    this.emit("close_")
  }

  private emitError(msg: string): void {
    this.state = TcpState.CLOSED
    this.cleanup()
    this.destroy(new Error(msg))
  }

  /** Connection key for lookup */
  get key(): string {
    return connectionKey(this.localPort, this.remotePort, this.remoteIP)
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

function parseIPAddress(ip: string): Uint8Array {
  const parts = ip.split(".").map(Number)
  return new Uint8Array(parts)
}

/** Ephemeral port allocator */
let nextEphemeralPort = 49152

function allocatePort(): number {
  const port = nextEphemeralPort++
  if (nextEphemeralPort > 65535) nextEphemeralPort = 49152
  return port
}

export class TcpStack extends EventEmitter {
  private device: Device
  private connections: Map<string, TcpConnection> = new Map()
  private localIP: Uint8Array

  constructor(device: Device, localIP: string) {
    super()
    this.device = device
    this.localIP = parseIPAddress(localIP)

    // Listen for incoming IP packets from the WireGuard tunnel
    this.device.on("packet", (data: Uint8Array, _peer: Peer) => {
      this.handleIPPacket(data)
    })
  }

  /** Create a new outbound TCP connection through the WireGuard tunnel */
  connect(host: string, port: number, peer: Peer): TcpConnection {
    const remoteIP = parseIPAddress(host)
    const localPort = allocatePort()

    const conn = new TcpConnection(this.localIP, remoteIP, localPort, port, peer, this.device)

    const key = connectionKey(localPort, port, remoteIP)
    this.connections.set(key, conn)

    conn.on("close_", () => {
      this.connections.delete(key)
    })

    conn.connect_()
    return conn
  }

  private handleIPPacket(packet: Uint8Array): void {
    const ip = parseIPv4(packet)
    if (!ip) return
    if (ip.protocol !== IP_PROTO_TCP) return

    const tcp = parseTCPSegment(ip.payload)
    if (!tcp) return

    // Find matching connection
    const key = connectionKey(tcp.dstPort, tcp.srcPort, ip.src)
    const conn = this.connections.get(key)
    if (!conn) {
      // No connection — send RST if it's not already a RST
      if (!(tcp.flags & TCP_RST)) {
        this.sendRST(ip, tcp)
      }
      return
    }

    conn.handlePacket(tcp)
  }

  private sendRST(ip: { src: Uint8Array; dst: Uint8Array }, tcp: TCPHeader): void {
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
      ip.dst, // our IP
      ip.src, // their IP
    )

    const ipPacket = buildIPv4Header(ip.dst, ip.src, IP_PROTO_TCP, segment, 0)
    // Find any peer to send through
    const peers = this.device.getPeers()
    if (peers[0]) {
      this.device.sendPacket(peers[0], ipPacket)
    }
  }

  destroy(): void {
    for (const conn of this.connections.values()) {
      conn.destroy()
    }
    this.connections.clear()
  }
}

// Export helpers for testing
export { parseIPv4, parseTCPSegment, parseIPAddress }
