import { test, expect } from "bun:test"
import * as Blake2s from "./Blake2s.ts"

test("blake2s-256 empty input", () => {
  const hash = Blake2s.blake2s256(new Uint8Array(0))
  expect(hash.length).toBe(32)
  // Known test vector: BLAKE2s-256("") = 69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9
  const expected = "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"
  expect(Buffer.from(hash).toString("hex")).toBe(expected)
})

test("blake2s-256 abc", () => {
  const hash = Blake2s.blake2s256(new TextEncoder().encode("abc"))
  expect(hash.length).toBe(32)
  // Known: BLAKE2s-256("abc") = 508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982
  const expected = "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
  expect(Buffer.from(hash).toString("hex")).toBe(expected)
})

test("blake2s-128 keyed", () => {
  const key = new Uint8Array(32)
  key.fill(0x42)
  const mac = Blake2s.blake2s128(key, new TextEncoder().encode("test"))
  expect(mac.length).toBe(16)
})

test("blake2s incremental update", () => {
  const data = new TextEncoder().encode("hello world")
  const oneShot = Blake2s.blake2s256(data)

  const h = new Blake2s.Blake2s(32)
  h.update(new TextEncoder().encode("hello "))
  h.update(new TextEncoder().encode("world"))
  const incremental = h.digest()

  expect(Buffer.from(oneShot).toString("hex")).toBe(Buffer.from(incremental).toString("hex"))
})

test("hmac-blake2s-256", () => {
  const key = new Uint8Array(32).fill(0x0b)
  const data = new TextEncoder().encode("Hi There")
  const mac = Blake2s.hmacBlake2s256(key, data)
  expect(mac.length).toBe(32)
})

test("noise protocol initial chain key", () => {
  // InitialChainKey = BLAKE2s-256("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")
  const chainKey = Blake2s.blake2s256(
    new TextEncoder().encode("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"),
  )
  expect(chainKey.length).toBe(32)
  // This should be a deterministic value
  const hex = Buffer.from(chainKey).toString("hex")
  expect(hex.length).toBe(64)
})
