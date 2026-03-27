/**
 * WireGuard MAC1/MAC2 and cookie mechanism.
 * Direct port from wireguard-go/device/cookie.go.
 */
import * as NCrypto from "node:crypto"
import * as Blake2s from "../crypto/Blake2s.ts"
import * as ChaCha20Poly1305 from "../crypto/ChaCha20Poly1305.ts"
import * as Handshake from "./Handshake.ts"

function hmacEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false
  let result = 0
  for (let i = 0; i < a.length; i++) {
    result |= a[i]! ^ b[i]!
  }
  return result === 0
}

export class CookieChecker {
  #mac1Key: Uint8Array
  #mac2EncryptionKey: Uint8Array
  #mac2Secret: Uint8Array = new Uint8Array(32)
  #mac2SecretSet: number = 0

  constructor(publicKey: Uint8Array) {
    // mac1 key = BLAKE2s-256("mac1----" || pk)
    const mac1Hash = new Blake2s.Blake2s(32)
    mac1Hash.update(new TextEncoder().encode(Handshake.WGLabelMAC1))
    mac1Hash.update(publicKey)
    this.#mac1Key = mac1Hash.digest()

    // mac2 encryption key = BLAKE2s-256("cookie--" || pk)
    const mac2Hash = new Blake2s.Blake2s(32)
    mac2Hash.update(new TextEncoder().encode(Handshake.WGLabelCookie))
    mac2Hash.update(publicKey)
    this.#mac2EncryptionKey = mac2Hash.digest()
  }

  checkMAC1(msg: Uint8Array): boolean {
    const size = msg.length
    const smac2 = size - 16
    const smac1 = smac2 - 16

    const mac1 = Blake2s.blake2s128(this.#mac1Key, msg.subarray(0, smac1))
    return hmacEqual(mac1, msg.subarray(smac1, smac2))
  }

  checkMAC2(msg: Uint8Array, src: Uint8Array): boolean {
    if (Date.now() - this.#mac2SecretSet > Handshake.CookieRefreshTime) return false

    const cookie = Blake2s.blake2s128(this.#mac2Secret, src)
    const smac2 = msg.length - 16
    const mac2 = Blake2s.blake2s128(cookie, msg.subarray(0, smac2))
    return hmacEqual(mac2, msg.subarray(smac2))
  }

  createReply(msg: Uint8Array, receiverIndex: number, src: Uint8Array): Uint8Array {
    // Refresh secret if needed
    if (Date.now() - this.#mac2SecretSet > Handshake.CookieRefreshTime) {
      const secret = NCrypto.randomBytes(32)
      this.#mac2Secret = new Uint8Array(secret)
      this.#mac2SecretSet = Date.now()
    }

    // Derive cookie
    const cookie = Blake2s.blake2s128(this.#mac2Secret, src)

    // Extract MAC1 from msg for AAD
    const size = msg.length
    const smac2 = size - 16
    const smac1 = smac2 - 16

    // Encrypt cookie
    const nonce = new Uint8Array(NCrypto.randomBytes(24))
    const encryptedCookie = ChaCha20Poly1305.xSeal(
      this.#mac2EncryptionKey,
      nonce,
      cookie,
      msg.subarray(smac1, smac2),
    )

    // Marshal reply (64 bytes)
    const reply = new Uint8Array(Handshake.MessageCookieReplySize)
    const view = new DataView(reply.buffer)
    view.setUint32(0, Handshake.MessageCookieReplyType, true)
    view.setUint32(4, receiverIndex, true)
    reply.set(nonce, 8)
    reply.set(encryptedCookie, 32)

    return reply
  }
}

export class CookieGenerator {
  #mac1Key: Uint8Array
  #mac2EncryptionKey: Uint8Array
  #cookie: Uint8Array = new Uint8Array(16)
  #cookieSet: number = 0
  #hasLastMAC1: boolean = false
  #lastMAC1: Uint8Array = new Uint8Array(16)

  constructor(publicKey: Uint8Array) {
    const mac1Hash = new Blake2s.Blake2s(32)
    mac1Hash.update(new TextEncoder().encode(Handshake.WGLabelMAC1))
    mac1Hash.update(publicKey)
    this.#mac1Key = mac1Hash.digest()

    const mac2Hash = new Blake2s.Blake2s(32)
    mac2Hash.update(new TextEncoder().encode(Handshake.WGLabelCookie))
    mac2Hash.update(publicKey)
    this.#mac2EncryptionKey = mac2Hash.digest()
  }

  addMacs(msg: Uint8Array): void {
    const size = msg.length
    const smac2 = size - 16
    const smac1 = smac2 - 16

    const mac1 = Blake2s.blake2s128(this.#mac1Key, msg.subarray(0, smac1))
    msg.set(mac1, smac1)
    this.#lastMAC1 = new Uint8Array(mac1)
    this.hasLastMAC1 = true

    if (Date.now() - this.#cookieSet > Handshake.CookieRefreshTime) {
      return // Leave MAC2 as zeros
    }

    const mac2 = Blake2s.blake2s128(this.#cookie, msg.subarray(0, smac2))
    msg.set(mac2, smac2)
  }

  consumeReply(msg: Uint8Array): boolean {
    if (msg.length !== Handshake.MessageCookieReplySize) return false

    const view = new DataView(msg.buffer, msg.byteOffset, msg.byteLength)
    if (view.getUint32(0, true) !== Handshake.MessageCookieReplyType) return false

    if (!this.hasLastMAC1) return false

    const nonce = msg.slice(8, 32)
    const encryptedCookie = msg.slice(32, 64)

    const cookie = ChaCha20Poly1305.xOpen(
      this.#mac2EncryptionKey,
      nonce,
      encryptedCookie,
      this.#lastMAC1,
    )
    if (!cookie) return false

    this.#cookie = cookie
    this.#cookieSet = Date.now()
    return true
  }
}
