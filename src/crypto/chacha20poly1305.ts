/**
 * ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD — backed by @noble/ciphers.
 */

import { chacha20poly1305, xchacha20poly1305 } from "@noble/ciphers/chacha.js"

const KEY_SIZE = 32
const NONCE_SIZE = 12
const TAG_SIZE = 16

export function seal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  return chacha20poly1305(key, nonce, aad).encrypt(plaintext)
}

export function open(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Uint8Array | null {
  try {
    return chacha20poly1305(key, nonce, aad).decrypt(ciphertext)
  } catch {
    return null
  }
}

export function xSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  return xchacha20poly1305(key, nonce, aad).encrypt(plaintext)
}

export function xOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  aad?: Uint8Array,
): Uint8Array | null {
  try {
    return xchacha20poly1305(key, nonce, aad).decrypt(ciphertext)
  } catch {
    return null
  }
}

export { KEY_SIZE, NONCE_SIZE, TAG_SIZE }
