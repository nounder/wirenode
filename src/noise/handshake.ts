/**
 * WireGuard Noise_IKpsk2 handshake protocol.
 */
import * as NCrypto from "node:crypto"
import * as Blake2s from "../crypto/Blake2s.ts"
import * as ChaCha20Poly1305 from "../crypto/ChaCha20Poly1305.ts"
import * as Curve25519 from "../crypto/Curve25519.ts"
import * as Kdf from "./Kdf.ts"
import * as Tai64n from "./Tai64n.ts"
import * as Replay from "./Replay.ts"

// Protocol constants
const NoiseConstruction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
const WGIdentifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"
export const WGLabelMAC1 = "mac1----"
export const WGLabelCookie = "cookie--"

// Message types
export const MessageInitiationType = 1
export const MessageResponseType = 2
export const MessageCookieReplyType = 3
export const MessageTransportType = 4

// Message sizes
export const MessageInitiationSize = 148
export const MessageResponseSize = 92
export const MessageCookieReplySize = 64
export const MessageTransportHeaderSize = 16
export const MessageTransportSize = MessageTransportHeaderSize + 16 // + poly1305 tag

// Transport offsets
export const MessageTransportOffsetReceiver = 4
export const MessageTransportOffsetCounter = 8
export const MessageTransportOffsetContent = 16

// Timing constants (ms)
export const RekeyAfterTime = 120_000
export const RejectAfterTime = 180_000
export const RekeyTimeout = 5_000
export const KeepaliveTimeout = 10_000
export const CookieRefreshTime = 120_000
export const HandshakeInitiationRate = 50
export const RekeyAfterMessages = Number.MAX_SAFE_INTEGER
export const RejectAfterMessages = Number.MAX_SAFE_INTEGER

const InitialChainKey = Blake2s.blake2s256(new TextEncoder().encode(NoiseConstruction))
const InitialHash = (() => {
  const h = new Blake2s.Blake2s(32)
  h.update(InitialChainKey)
  h.update(new TextEncoder().encode(WGIdentifier))
  return h.digest()
})()

const ZeroNonce = new Uint8Array(12)

export const HandshakeState = {
  Zeroed: 0,
  InitiationCreated: 1,
  InitiationConsumed: 2,
  ResponseCreated: 3,
  ResponseConsumed: 4,
} as const
export type HandshakeState = typeof HandshakeState[keyof typeof HandshakeState]

export interface Keypair {
  sendKey: Uint8Array
  receiveKey: Uint8Array
  sendNonce: number
  localIndex: number
  remoteIndex: number
  created: number // Date.now()
  isInitiator: boolean
  replayFilter: Replay.ReplayFilter
}

export interface HandshakeContext {
  state: HandshakeState
  hash: Uint8Array
  chainKey: Uint8Array
  presharedKey: Uint8Array
  localEphemeral: Uint8Array // private key
  localIndex: number
  remoteIndex: number
  remoteStatic: Uint8Array // public key
  remoteEphemeral: Uint8Array // public key
  precomputedStaticStatic: Uint8Array
  lastTimestamp: Uint8Array
  lastInitiationConsumption: number // Date.now()
}

function setZero(arr: Uint8Array) {
  arr.fill(0)
}

function mixHash(hash: Uint8Array, data: Uint8Array): Uint8Array {
  const h = new Blake2s.Blake2s(32)
  h.update(hash)
  h.update(data)
  return h.digest()
}

function mixKey(chainKey: Uint8Array, data: Uint8Array): Uint8Array {
  return Kdf.KDF1(chainKey, data)
}

function newIndex(): number {
  const buf = NCrypto.randomBytes(4)
  return buf.readUInt32LE(0)
}

export function createHandshake(
  remoteStatic: Uint8Array,
  presharedKey: Uint8Array,
  localStaticPrivate: Uint8Array,
): HandshakeContext {
  const precomputed = Curve25519.sharedSecret(localStaticPrivate, remoteStatic)
  return {
    state: HandshakeState.Zeroed,
    hash: new Uint8Array(32),
    chainKey: new Uint8Array(32),
    presharedKey: new Uint8Array(presharedKey),
    localEphemeral: new Uint8Array(32),
    localIndex: 0,
    remoteIndex: 0,
    remoteStatic: new Uint8Array(remoteStatic),
    remoteEphemeral: new Uint8Array(32),
    precomputedStaticStatic: precomputed,
    lastTimestamp: new Uint8Array(Tai64n.TIMESTAMP_SIZE),
    lastInitiationConsumption: 0,
  }
}

export function createMessageInitiation(
  handshake: HandshakeContext,
  localStaticPublic: Uint8Array,
  localStaticPrivate: Uint8Array,
): Uint8Array {
  // Reset hash and chain key
  handshake.hash = new Uint8Array(InitialHash)
  handshake.chainKey = new Uint8Array(InitialChainKey)

  // Generate ephemeral key
  handshake.localEphemeral = Curve25519.generatePrivateKey()
  const ephemeralPublic = Curve25519.publicKey(handshake.localEphemeral)

  // mixHash(remoteStatic)
  handshake.hash = mixHash(handshake.hash, handshake.remoteStatic)

  // mixKey + mixHash(ephemeral)
  handshake.chainKey = mixKey(handshake.chainKey, ephemeralPublic)
  handshake.hash = mixHash(handshake.hash, ephemeralPublic)

  // Encrypt static key: DH(ephemeral, remoteStatic)
  const ss1 = Curve25519.sharedSecret(handshake.localEphemeral, handshake.remoteStatic)
  const [chainKey2, key1] = Kdf.KDF2(handshake.chainKey, ss1)
  handshake.chainKey = chainKey2

  const encryptedStatic = ChaCha20Poly1305.seal(key1, ZeroNonce, localStaticPublic, handshake.hash)
  handshake.hash = mixHash(handshake.hash, encryptedStatic)

  // Encrypt timestamp: DH(static, static)
  if (Curve25519.isZero(handshake.precomputedStaticStatic)) {
    throw new Error("invalid precomputed static-static")
  }

  const [chainKey3, key2] = Kdf.KDF2(handshake.chainKey, handshake.precomputedStaticStatic)
  handshake.chainKey = chainKey3

  const timestamp = Tai64n.now()
  const encryptedTimestamp = ChaCha20Poly1305.seal(key2, ZeroNonce, timestamp, handshake.hash)

  // Assign index
  handshake.localIndex = newIndex()

  handshake.hash = mixHash(handshake.hash, encryptedTimestamp)
  handshake.state = HandshakeState.InitiationCreated

  // Marshal message (148 bytes)
  const msg = new Uint8Array(MessageInitiationSize)
  const view = new DataView(msg.buffer)
  view.setUint32(0, MessageInitiationType, true)
  view.setUint32(4, handshake.localIndex, true)
  msg.set(ephemeralPublic, 8)
  msg.set(encryptedStatic, 40) // 32 + 16 = 48 bytes
  msg.set(encryptedTimestamp, 88) // 12 + 16 = 28 bytes
  // MAC1 and MAC2 are filled in by addMacs()

  return msg
}

export function consumeMessageInitiation(
  msg: Uint8Array,
  localStaticPublic: Uint8Array,
  localStaticPrivate: Uint8Array,
  lookupPeer: (publicKey: Uint8Array) => HandshakeContext | null,
): { peer: HandshakeContext } | null {
  if (msg.length !== MessageInitiationSize) return null

  const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength)
  if (view.getUint32(0, true) !== MessageInitiationType) return null

  const senderIndex = view.getUint32(4, true)
  const ephemeral = msg.slice(8, 40)
  const encryptedStatic = msg.slice(40, 88) // 48 bytes
  const encryptedTimestamp = msg.slice(88, 116) // 28 bytes

  let hash = new Uint8Array(InitialHash)
  let chainKey = new Uint8Array(InitialChainKey)

  // mixHash(localStaticPublic)
  hash = mixHash(hash, localStaticPublic)
  // mixHash(ephemeral)
  hash = mixHash(hash, ephemeral)
  // mixKey(ephemeral)
  chainKey = mixKey(chainKey, ephemeral)

  // Decrypt static key
  const ss1 = Curve25519.sharedSecret(localStaticPrivate, ephemeral)
  const [chainKey2, key1] = Kdf.KDF2(chainKey, ss1)
  chainKey = chainKey2

  const peerPK = ChaCha20Poly1305.open(key1, ZeroNonce, encryptedStatic, hash)
  if (!peerPK) return null
  hash = mixHash(hash, encryptedStatic)

  // Lookup peer
  const peer = lookupPeer(peerPK)
  if (!peer) return null

  // Decrypt timestamp
  if (Curve25519.isZero(peer.precomputedStaticStatic)) return null

  const [chainKey3, key2] = Kdf.KDF2(chainKey, peer.precomputedStaticStatic)
  chainKey = chainKey3

  const timestamp = ChaCha20Poly1305.open(key2, ZeroNonce, encryptedTimestamp, hash)
  if (!timestamp) return null
  hash = mixHash(hash, encryptedTimestamp)

  // Replay protection
  if (!Tai64n.after(timestamp, peer.lastTimestamp)) return null

  // Flood protection
  if (Date.now() - peer.lastInitiationConsumption <= HandshakeInitiationRate) return null

  // Update state
  peer.hash = hash
  peer.chainKey = chainKey
  peer.remoteIndex = senderIndex
  peer.remoteEphemeral = ephemeral
  peer.lastTimestamp = timestamp
  peer.lastInitiationConsumption = Date.now()
  peer.state = HandshakeState.InitiationConsumed

  return { peer }
}

export function createMessageResponse(handshake: HandshakeContext): Uint8Array {
  if (handshake.state !== HandshakeState.InitiationConsumed) {
    throw new Error("initiation must be consumed first")
  }

  // Assign index
  handshake.localIndex = newIndex()

  // Generate ephemeral key
  handshake.localEphemeral = Curve25519.generatePrivateKey()
  const ephemeralPublic = Curve25519.publicKey(handshake.localEphemeral)

  handshake.hash = mixHash(handshake.hash, ephemeralPublic)
  handshake.chainKey = mixKey(handshake.chainKey, ephemeralPublic)

  // 3 DH operations
  const ss1 = Curve25519.sharedSecret(handshake.localEphemeral, handshake.remoteEphemeral)
  handshake.chainKey = mixKey(handshake.chainKey, ss1)

  const ss2 = Curve25519.sharedSecret(handshake.localEphemeral, handshake.remoteStatic)
  handshake.chainKey = mixKey(handshake.chainKey, ss2)

  // PSK
  const [chainKey4, tau, key] = Kdf.KDF3(handshake.chainKey, handshake.presharedKey)
  handshake.chainKey = chainKey4
  handshake.hash = mixHash(handshake.hash, tau)

  // Encrypt empty (just auth tag)
  const encryptedEmpty = ChaCha20Poly1305.seal(key, ZeroNonce, new Uint8Array(0), handshake.hash)
  handshake.hash = mixHash(handshake.hash, encryptedEmpty)

  handshake.state = HandshakeState.ResponseCreated

  // Marshal message (92 bytes)
  const msg = new Uint8Array(MessageResponseSize)
  const view = new DataView(msg.buffer)
  view.setUint32(0, MessageResponseType, true)
  view.setUint32(4, handshake.localIndex, true)
  view.setUint32(8, handshake.remoteIndex, true)
  msg.set(ephemeralPublic, 12)
  msg.set(encryptedEmpty, 44) // 16 bytes (empty ciphertext + tag)
  // MAC1 and MAC2 filled by addMacs()

  return msg
}

export function consumeMessageResponse(
  msg: Uint8Array,
  handshake: HandshakeContext,
  localStaticPrivate: Uint8Array,
): boolean {
  if (msg.length !== MessageResponseSize) return false

  const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength)
  if (view.getUint32(0, true) !== MessageResponseType) return false

  const senderIndex = view.getUint32(4, true)
  const receiverIndex = view.getUint32(8, true)

  if (receiverIndex !== handshake.localIndex) return false
  if (handshake.state !== HandshakeState.InitiationCreated) return false

  const ephemeral = msg.slice(12, 44)
  const encryptedEmpty = msg.slice(44, 60) // 16 bytes

  let hash = mixHash(handshake.hash, ephemeral)
  let chainKey = mixKey(handshake.chainKey, ephemeral)

  // Finish 3-way DH
  const ss1 = Curve25519.sharedSecret(handshake.localEphemeral, ephemeral)
  chainKey = mixKey(chainKey, ss1)

  const ss2 = Curve25519.sharedSecret(localStaticPrivate, ephemeral)
  chainKey = mixKey(chainKey, ss2)

  // PSK
  const [chainKey4, tau, key] = Kdf.KDF3(chainKey, handshake.presharedKey)
  chainKey = chainKey4
  hash = mixHash(hash, tau)

  // Verify
  const result = ChaCha20Poly1305.open(key, ZeroNonce, encryptedEmpty, hash)
  if (!result) return false
  hash = mixHash(hash, encryptedEmpty)

  // Update state
  handshake.hash = hash
  handshake.chainKey = chainKey
  handshake.remoteIndex = senderIndex
  handshake.state = HandshakeState.ResponseConsumed

  return true
}

export function beginSymmetricSession(handshake: HandshakeContext): Keypair {
  let sendKey: Uint8Array
  let recvKey: Uint8Array
  let isInitiator: boolean

  if (handshake.state === HandshakeState.ResponseConsumed) {
    ;[sendKey, recvKey] = Kdf.KDF2(handshake.chainKey, new Uint8Array(0))
    isInitiator = true
  } else if (handshake.state === HandshakeState.ResponseCreated) {
    ;[recvKey, sendKey] = Kdf.KDF2(handshake.chainKey, new Uint8Array(0))
    isInitiator = false
  } else {
    throw new Error(`invalid state for keypair derivation: ${handshake.state}`)
  }

  // Zero handshake material
  setZero(handshake.chainKey)
  setZero(handshake.hash)
  setZero(handshake.localEphemeral)
  handshake.state = HandshakeState.Zeroed

  return {
    sendKey,
    receiveKey: recvKey,
    sendNonce: 0,
    localIndex: handshake.localIndex,
    remoteIndex: handshake.remoteIndex,
    created: Date.now(),
    isInitiator,
    replayFilter: new Replay.ReplayFilter(),
  }
}
