/**
 * X25519 key exchange — backed by @noble/curves.
 */

import { x25519 } from "@noble/curves/ed25519.js"
import { randomBytes } from "crypto"

const KEY_SIZE = 32

export function generatePrivateKey(): Uint8Array {
  const sk = new Uint8Array(randomBytes(KEY_SIZE))
  clampPrivateKey(sk)
  return sk
}

export function clampPrivateKey(sk: Uint8Array): void {
  sk[0]! &= 248
  sk[31] = (sk[31]! & 127) | 64
}

export function publicKey(sk: Uint8Array): Uint8Array {
  return x25519.getPublicKey(sk)
}

export function sharedSecret(sk: Uint8Array, pk: Uint8Array): Uint8Array {
  return x25519.getSharedSecret(sk, pk)
}

export function isZero(data: Uint8Array): boolean {
  let acc = 0
  for (let i = 0; i < data.length; i++) {
    acc |= data[i]!
  }
  return acc === 0
}

export { KEY_SIZE }
