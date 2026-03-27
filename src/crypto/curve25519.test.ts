import { test, expect } from "bun:test"
import * as Curve25519 from "./Curve25519.ts"

test("generate private key is 32 bytes and clamped", () => {
  const sk = Curve25519.generatePrivateKey()
  expect(sk.length).toBe(32)
  // Check clamping
  expect(sk[0]! & 7).toBe(0) // lower 3 bits cleared
  expect(sk[31]! & 128).toBe(0) // bit 255 cleared
  expect(sk[31]! & 64).toBe(64) // bit 254 set
})

test("public key derivation is deterministic", () => {
  const sk = Curve25519.generatePrivateKey()
  const pk1 = Curve25519.publicKey(sk)
  const pk2 = Curve25519.publicKey(sk)
  expect(Buffer.from(pk1).toString("hex")).toBe(Buffer.from(pk2).toString("hex"))
  expect(pk1.length).toBe(32)
})

test("shared secret is symmetric", () => {
  const sk1 = Curve25519.generatePrivateKey()
  const pk1 = Curve25519.publicKey(sk1)
  const sk2 = Curve25519.generatePrivateKey()
  const pk2 = Curve25519.publicKey(sk2)

  const ss1 = Curve25519.sharedSecret(sk1, pk2)
  const ss2 = Curve25519.sharedSecret(sk2, pk1)
  expect(Buffer.from(ss1).toString("hex")).toBe(Buffer.from(ss2).toString("hex"))
  expect(ss1.length).toBe(32)
})

test("isZero", () => {
  expect(Curve25519.isZero(new Uint8Array(32))).toBe(true)
  const nonZero = new Uint8Array(32)
  nonZero[16] = 1
  expect(Curve25519.isZero(nonZero)).toBe(false)
})

test("clamp private key", () => {
  const sk = new Uint8Array(32).fill(0xff)
  Curve25519.clampPrivateKey(sk)
  expect(sk[0]).toBe(0xf8)
  expect(sk[31]).toBe(0x7f)
})

test("known test vector (RFC 7748)", () => {
  // Alice's private key (clamped)
  const aliceSk = new Uint8Array([
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
  ])

  // Bob's private key (clamped)
  const bobSk = new Uint8Array([
    0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
    0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
  ])

  const alicePk = Curve25519.publicKey(aliceSk)
  const bobPk = Curve25519.publicKey(bobSk)

  // Alice's public key should be: 8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a
  expect(Buffer.from(alicePk).toString("hex")).toBe(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
  )

  // Shared secret should be: 4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742
  const ss = Curve25519.sharedSecret(aliceSk, bobPk)
  expect(Buffer.from(ss).toString("hex")).toBe(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
  )
})
