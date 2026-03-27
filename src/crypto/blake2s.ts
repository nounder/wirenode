/**
 * BLAKE2s hashing and HMAC — backed by @noble/hashes.
 */

import { blake2s } from "@noble/hashes/blake2.js"
import { hmac } from "@noble/hashes/hmac.js"

export class Blake2s {
  private h: ReturnType<typeof blake2s.create>

  constructor(outLen: number = 32, key?: Uint8Array) {
    this.h = blake2s.create({ dkLen: outLen, key })
  }

  update(data: Uint8Array): this {
    this.h.update(data)
    return this
  }

  digest(): Uint8Array {
    return this.h.digest()
  }
}

export function blake2s256(data: Uint8Array): Uint8Array {
  return blake2s(data)
}

export function blake2s128(key: Uint8Array, data: Uint8Array): Uint8Array {
  return blake2s(data, { key, dkLen: 16 })
}

export function blake2s256Keyed(key: Uint8Array, data: Uint8Array): Uint8Array {
  return blake2s(data, { key, dkLen: 32 })
}

export function hmacBlake2s256(key: Uint8Array, ...inputs: Uint8Array[]): Uint8Array {
  if (inputs.length === 1) {
    return hmac(blake2s, key, inputs[0]!)
  }
  // Multi-input: concatenate
  let len = 0
  for (const inp of inputs) len += inp.length
  const combined = new Uint8Array(len)
  let off = 0
  for (const inp of inputs) {
    combined.set(inp, off)
    off += inp.length
  }
  return hmac(blake2s, key, combined)
}
