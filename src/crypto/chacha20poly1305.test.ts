import { test, expect } from "bun:test"
import * as ChaCha20Poly1305 from "./ChaCha20Poly1305.ts"
import * as NCrypto from "node:crypto"

test("chacha20-poly1305 seal/open round-trip", () => {
  const key = new Uint8Array(NCrypto.randomBytes(32))
  const nonce = new Uint8Array(NCrypto.randomBytes(12))
  const plaintext = new TextEncoder().encode("Hello, WireGuard!")

  const ciphertext = ChaCha20Poly1305.seal(key, nonce, plaintext)
  expect(ciphertext.length).toBe(plaintext.length + 16) // + poly1305 tag

  const decrypted = ChaCha20Poly1305.open(key, nonce, ciphertext)
  expect(decrypted).not.toBeNull()
  expect(Buffer.from(decrypted!).toString()).toBe("Hello, WireGuard!")
})

test("chacha20-poly1305 with AAD", () => {
  const key = new Uint8Array(NCrypto.randomBytes(32))
  const nonce = new Uint8Array(NCrypto.randomBytes(12))
  const plaintext = new TextEncoder().encode("secret data")
  const aad = new TextEncoder().encode("additional data")

  const ciphertext = ChaCha20Poly1305.seal(key, nonce, plaintext, aad)
  const decrypted = ChaCha20Poly1305.open(key, nonce, ciphertext, aad)
  expect(decrypted).not.toBeNull()
  expect(Buffer.from(decrypted!).toString()).toBe("secret data")

  // Should fail with wrong AAD
  const wrongAad = new TextEncoder().encode("wrong data")
  const result = ChaCha20Poly1305.open(key, nonce, ciphertext, wrongAad)
  expect(result).toBeNull()
})

test("chacha20-poly1305 empty plaintext (auth only)", () => {
  const key = new Uint8Array(NCrypto.randomBytes(32))
  const nonce = new Uint8Array(12)
  const aad = new Uint8Array(NCrypto.randomBytes(32))

  const ciphertext = ChaCha20Poly1305.seal(key, nonce, new Uint8Array(0), aad)
  expect(ciphertext.length).toBe(16) // just the tag

  const decrypted = ChaCha20Poly1305.open(key, nonce, ciphertext, aad)
  expect(decrypted).not.toBeNull()
  expect(decrypted!.length).toBe(0)
})

test("chacha20-poly1305 tamper detection", () => {
  const key = new Uint8Array(NCrypto.randomBytes(32))
  const nonce = new Uint8Array(NCrypto.randomBytes(12))
  const plaintext = new TextEncoder().encode("sensitive")

  const ciphertext = ChaCha20Poly1305.seal(key, nonce, plaintext)

  // Tamper with ciphertext
  const tampered = new Uint8Array(ciphertext)
  tampered[0] ^= 0xff
  const result = ChaCha20Poly1305.open(key, nonce, tampered)
  expect(result).toBeNull()
})

test("xchacha20-poly1305 seal/open round-trip", () => {
  const key = new Uint8Array(NCrypto.randomBytes(32))
  const nonce = new Uint8Array(NCrypto.randomBytes(24)) // 24-byte nonce

  const plaintext = new TextEncoder().encode("XChaCha20 test!")
  const ciphertext = ChaCha20Poly1305.xSeal(key, nonce, plaintext)
  expect(ciphertext.length).toBe(plaintext.length + 16)

  const decrypted = ChaCha20Poly1305.xOpen(key, nonce, ciphertext)
  expect(decrypted).not.toBeNull()
  expect(Buffer.from(decrypted!).toString()).toBe("XChaCha20 test!")
})

test("xchacha20-poly1305 with AAD", () => {
  const key = new Uint8Array(NCrypto.randomBytes(32))
  const nonce = new Uint8Array(NCrypto.randomBytes(24))
  const plaintext = new TextEncoder().encode("cookie data")
  const aad = new TextEncoder().encode("mac1 value")

  const ciphertext = ChaCha20Poly1305.xSeal(key, nonce, plaintext, aad)
  const decrypted = ChaCha20Poly1305.xOpen(key, nonce, ciphertext, aad)
  expect(decrypted).not.toBeNull()
  expect(Buffer.from(decrypted!).toString()).toBe("cookie data")
})
