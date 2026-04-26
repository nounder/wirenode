/**
 * WireGuard peer management.
 * Handles handshake state, keypair rotation, and timers.
 */

import * as Handshake from "../noise/Handshake.ts"
import * as TypedEmitter from "../util/TypedEmitter.ts"

export interface PeerConfig {
  publicKey: Uint8Array
  presharedKey: Uint8Array
  endpoint?: string // host:port
  persistentKeepalive: number // seconds, 0 = disabled
  allowedIPs: string[] // CIDR strings
}

export type PeerEvents = {
  keypairReady: []
  sendKeepalive: []
}

export interface Peer {
  events: TypedEmitter.TypedEmitter<PeerEvents>

  readonly publicKey: Uint8Array
  readonly publicKeyHex: string
  endpoint: string | null
  persistentKeepalive: number
  allowedIPs: string[]

  handshake: Handshake.HandshakeContext
  currentKeypair: Handshake.Keypair | null
  previousKeypair: Handshake.Keypair | null
  nextKeypair: Handshake.Keypair | null

  stagedPackets: Uint8Array[]

  keepaliveTimer: ReturnType<typeof setTimeout> | null
  handshakeTimer: ReturnType<typeof setTimeout> | null
  rekeyTimer: ReturnType<typeof setTimeout> | null
  zeroKeyTimer: ReturnType<typeof setTimeout> | null

  lastHandshakeAttempt: number
  lastSentPacket: number
  lastReceivedPacket: number
}

export function make(config: PeerConfig, localStaticPrivate: Uint8Array): Peer {
  return {
    events: TypedEmitter.make<PeerEvents>(),
    publicKey: config.publicKey,
    publicKeyHex: Buffer.from(config.publicKey).toString("hex"),
    endpoint: config.endpoint ?? null,
    persistentKeepalive: config.persistentKeepalive,
    allowedIPs: config.allowedIPs,
    handshake: Handshake.createHandshake(
      config.publicKey,
      config.presharedKey,
      localStaticPrivate,
    ),
    currentKeypair: null,
    previousKeypair: null,
    nextKeypair: null,
    stagedPackets: [],
    keepaliveTimer: null,
    handshakeTimer: null,
    rekeyTimer: null,
    zeroKeyTimer: null,
    lastHandshakeAttempt: 0,
    lastSentPacket: 0,
    lastReceivedPacket: 0,
  }
}

export function activateKeypair(self: Peer): void {
  const keypair = Handshake.beginSymmetricSession(self.handshake)

  if (keypair.isInitiator) {
    if (self.nextKeypair) {
      self.previousKeypair = self.nextKeypair
      self.nextKeypair = null
    } else {
      self.previousKeypair = self.currentKeypair
    }
    self.currentKeypair = keypair
  } else {
    self.nextKeypair = keypair
    self.previousKeypair = null
  }

  self.events.emit("keypairReady")
}

export function receivedWithKeypair(self: Peer, keypair: Handshake.Keypair): boolean {
  if (self.nextKeypair !== keypair) return false
  self.previousKeypair = self.currentKeypair
  self.currentKeypair = self.nextKeypair
  self.nextKeypair = null
  return true
}

export function needsRekey(self: Peer): boolean {
  const kp = self.currentKeypair
  if (!kp) return true
  if (!kp.isInitiator) return false
  if (Date.now() - kp.created > Handshake.RekeyAfterTime) return true
  if (kp.sendNonce > Handshake.RekeyAfterMessages) return true
  return false
}

export function isKeypairExpired(_self: Peer, kp: Handshake.Keypair | null): boolean {
  if (!kp) return true
  return Date.now() - kp.created > Handshake.RejectAfterTime
}

export function getSendKeypair(self: Peer): Handshake.Keypair | null {
  const kp = self.currentKeypair
  if (!kp) return null
  if (isKeypairExpired(self, kp)) return null
  if (kp.sendNonce >= Handshake.RejectAfterMessages) return null
  return kp
}

export function findKeypairByIndex(self: Peer, index: number): Handshake.Keypair | null {
  if (self.currentKeypair?.localIndex === index) return self.currentKeypair
  if (self.previousKeypair?.localIndex === index) return self.previousKeypair
  if (self.nextKeypair?.localIndex === index) return self.nextKeypair
  return null
}

export function startKeepalive(self: Peer): void {
  stopKeepalive(self)
  if (self.persistentKeepalive > 0) {
    self.keepaliveTimer = setInterval(() => {
      self.events.emit("sendKeepalive")
    }, self.persistentKeepalive * 1000)
  }
}

export function stopKeepalive(self: Peer): void {
  if (self.keepaliveTimer) {
    clearInterval(self.keepaliveTimer)
    self.keepaliveTimer = null
  }
}

export function destroy(self: Peer): void {
  stopKeepalive(self)
  if (self.handshakeTimer) clearTimeout(self.handshakeTimer)
  if (self.rekeyTimer) clearTimeout(self.rekeyTimer)
  if (self.zeroKeyTimer) clearTimeout(self.zeroKeyTimer)
  self.events.removeAllListeners()
}
