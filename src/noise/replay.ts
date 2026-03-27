/**
 * Anti-replay filter implementing RFC 6479 sliding window.
 * Direct port from wireguard-go/replay/replay.go.
 */

const BLOCK_BIT_LOG = 6 // 1<<6 == 64 bits
const BLOCK_BITS = 1 << BLOCK_BIT_LOG // 64
const RING_BLOCKS = 1 << 7 // 128
const WINDOW_SIZE = (RING_BLOCKS - 1) * BLOCK_BITS // 8128
const BLOCK_MASK = RING_BLOCKS - 1 // 127
const BIT_MASK = BLOCK_BITS - 1 // 63

// We use BigInt for the 64-bit block values since JS bitwise ops are 32-bit.
// However, the counter values fit in Number (safe up to 2^53).
// The ring blocks need full 64-bit bitwise, so we use BigInt[].

export class ReplayFilter {
  private last: number = 0
  private ring: BigInt[] = new Array(RING_BLOCKS).fill(0n)

  reset(): void {
    this.last = 0
    this.ring.fill(0n)
  }

  validateCounter(counter: number, limit: number): boolean {
    if (counter >= limit) return false

    const indexBlock = counter >>> BLOCK_BIT_LOG

    if (counter > this.last) {
      // Move window forward
      const current = this.last >>> BLOCK_BIT_LOG
      let diff = indexBlock - current
      if (diff > RING_BLOCKS) diff = RING_BLOCKS
      for (let i = current + 1; i <= current + diff; i++) {
        this.ring[i & BLOCK_MASK] = 0n
      }
      this.last = counter
    } else if (this.last - counter > WINDOW_SIZE) {
      // Behind current window
      return false
    }

    // Check and set bit
    const ib = indexBlock & BLOCK_MASK
    const indexBit = BigInt(counter & BIT_MASK)
    const old = this.ring[ib] as bigint
    const updated = old | (1n << indexBit)
    this.ring[ib] = updated
    return old !== updated
  }
}
