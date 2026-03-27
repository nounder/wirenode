/**
 * WireGuard peer management.
 * Handles handshake state, keypair rotation, and timers.
 */

import { EventEmitter } from "events"
import * as Handshake from "../noise/Handshake.ts"

export interface PeerConfig {
  publicKey: Uint8Array
  presharedKey: Uint8Array
  endpoint?: string // host:port
  persistentKeepalive: number // seconds, 0 = disabled
  allowedIPs: string[] // CIDR strings
}

export class Peer extends EventEmitter {
  readonly publicKey: Uint8Array
  readonly publicKeyHex: string
  endpoint: string | null
  persistentKeepalive: number
  allowedIPs: string[]

  handshake: Handshake.HandshakeContext
  currentKeypair: Handshake.Keypair | null = null
  previousKeypair: Handshake.Keypair | null = null
  nextKeypair: Handshake.Keypair | null = null

  // Queued packets waiting for a keypair
  stagedPackets: Uint8Array[] = []

  // Timers
  private keepaliveTimer: ReturnType<typeof setTimeout> | null = null
  private handshakeTimer: ReturnType<typeof setTimeout> | null = null
  private rekeyTimer: ReturnType<typeof setTimeout> | null = null
  private zeroKeyTimer: ReturnType<typeof setTimeout> | null = null

  lastHandshakeAttempt: number = 0
  lastSentPacket: number = 0
  lastReceivedPacket: number = 0

  constructor(config: PeerConfig, localStaticPrivate: Uint8Array) {
    super()
    this.publicKey = config.publicKey
    this.publicKeyHex = Buffer.from(config.publicKey).toString("hex")
    this.endpoint = config.endpoint ?? null
    this.persistentKeepalive = config.persistentKeepalive
    this.allowedIPs = config.allowedIPs
    this.handshake = Handshake.createHandshake(
      config.publicKey,
      config.presharedKey,
      localStaticPrivate,
    )
  }

  activateKeypair(): void {
    const keypair = Handshake.beginSymmetricSession(this.handshake)

    if (keypair.isInitiator) {
      if (this.nextKeypair) {
        this.previousKeypair = this.nextKeypair
        this.nextKeypair = null
      } else {
        this.previousKeypair = this.currentKeypair
      }
      this.currentKeypair = keypair
    } else {
      this.nextKeypair = keypair
      this.previousKeypair = null
    }

    // Flush staged packets
    this.emit("keypairReady")
  }

  receivedWithKeypair(keypair: Handshake.Keypair): boolean {
    if (this.nextKeypair !== keypair) return false
    this.previousKeypair = this.currentKeypair
    this.currentKeypair = this.nextKeypair
    this.nextKeypair = null
    return true
  }

  needsRekey(): boolean {
    const kp = this.currentKeypair
    if (!kp) return true
    if (!kp.isInitiator) return false
    if (Date.now() - kp.created > Handshake.RekeyAfterTime) return true
    if (kp.sendNonce > Handshake.RekeyAfterMessages) return true
    return false
  }

  isKeypairExpired(kp: Handshake.Keypair | null): boolean {
    if (!kp) return true
    return Date.now() - kp.created > Handshake.RejectAfterTime
  }

  getSendKeypair(): Handshake.Keypair | null {
    const kp = this.currentKeypair
    if (!kp) return null
    if (this.isKeypairExpired(kp)) return null
    if (kp.sendNonce >= Handshake.RejectAfterMessages) return null
    return kp
  }

  findKeypairByIndex(index: number): Handshake.Keypair | null {
    if (this.currentKeypair?.localIndex === index) return this.currentKeypair
    if (this.previousKeypair?.localIndex === index) return this.previousKeypair
    if (this.nextKeypair?.localIndex === index) return this.nextKeypair
    return null
  }

  startKeepalive(): void {
    this.stopKeepalive()
    if (this.persistentKeepalive > 0) {
      this.keepaliveTimer = setInterval(() => {
        this.emit("sendKeepalive")
      }, this.persistentKeepalive * 1000)
    }
  }

  stopKeepalive(): void {
    if (this.keepaliveTimer) {
      clearInterval(this.keepaliveTimer)
      this.keepaliveTimer = null
    }
  }

  destroy(): void {
    this.stopKeepalive()
    if (this.handshakeTimer) clearTimeout(this.handshakeTimer)
    if (this.rekeyTimer) clearTimeout(this.rekeyTimer)
    if (this.zeroKeyTimer) clearTimeout(this.zeroKeyTimer)
    this.removeAllListeners()
  }
}
