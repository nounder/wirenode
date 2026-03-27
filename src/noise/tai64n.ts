/**
 * TAI64N timestamp format as used in WireGuard.
 * 12 bytes: 8 bytes TAI64 seconds + 4 bytes nanoseconds.
 */

const TIMESTAMP_SIZE = 12
const BASE = BigInt("0x400000000000000a")
const WHITENER_MASK = 0x1000000 - 1

export function now(): Uint8Array {
  const ts = new Uint8Array(TIMESTAMP_SIZE)
  const view = new DataView(ts.buffer)

  const ms = Date.now()
  const secs = BigInt(Math.floor(ms / 1000))
  const nano = ((ms % 1000) * 1_000_000) & ~WHITENER_MASK

  const tai = BASE + secs
  view.setBigUint64(0, tai, false) // big-endian
  view.setUint32(8, nano >>> 0, false) // big-endian

  return ts
}

export function after(t1: Uint8Array, t2: Uint8Array): boolean {
  for (let i = 0; i < TIMESTAMP_SIZE; i++) {
    if (t1[i]! > t2[i]!) return true
    if (t1[i]! < t2[i]!) return false
  }
  return false
}

export { TIMESTAMP_SIZE }
