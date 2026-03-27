/**
 * WireGuard KDF functions.
 * HMAC-based Key Derivation using BLAKE2s-256 as the hash function.
 * Direct port from wireguard-go/device/noise-helpers.go.
 */

import * as Blake2s from "../crypto/Blake2s.ts"

export function HMAC1(key: Uint8Array, in0: Uint8Array): Uint8Array {
  return Blake2s.hmacBlake2s256(key, in0)
}

export function HMAC2(key: Uint8Array, in0: Uint8Array, in1: Uint8Array): Uint8Array {
  return Blake2s.hmacBlake2s256(key, in0, in1)
}

export function KDF1(key: Uint8Array, input: Uint8Array): Uint8Array {
  const prk = HMAC1(key, input)
  return HMAC1(prk, new Uint8Array([0x01]))
}

export function KDF2(key: Uint8Array, input: Uint8Array): [Uint8Array, Uint8Array] {
  const prk = HMAC1(key, input)
  const t0 = HMAC1(prk, new Uint8Array([0x01]))
  const t1 = HMAC2(prk, t0, new Uint8Array([0x02]))
  return [t0, t1]
}

export function KDF3(key: Uint8Array, input: Uint8Array): [Uint8Array, Uint8Array, Uint8Array] {
  const prk = HMAC1(key, input)
  const t0 = HMAC1(prk, new Uint8Array([0x01]))
  const t1 = HMAC2(prk, t0, new Uint8Array([0x02]))
  const t2 = HMAC2(prk, t1, new Uint8Array([0x03]))
  return [t0, t1, t2]
}
