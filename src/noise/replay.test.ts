import { test, expect } from "bun:test"
import * as Replay from "./Replay.ts"

test("accepts sequential counters", () => {
  const f = new Replay.ReplayFilter()
  const limit = Number.MAX_SAFE_INTEGER
  expect(f.validateCounter(0, limit)).toBe(true)
  expect(f.validateCounter(1, limit)).toBe(true)
  expect(f.validateCounter(2, limit)).toBe(true)
  expect(f.validateCounter(3, limit)).toBe(true)
})

test("rejects duplicate counters", () => {
  const f = new Replay.ReplayFilter()
  const limit = Number.MAX_SAFE_INTEGER
  expect(f.validateCounter(0, limit)).toBe(true)
  expect(f.validateCounter(0, limit)).toBe(false)
  expect(f.validateCounter(1, limit)).toBe(true)
  expect(f.validateCounter(1, limit)).toBe(false)
})

test("accepts out-of-order within window", () => {
  const f = new Replay.ReplayFilter()
  const limit = Number.MAX_SAFE_INTEGER
  expect(f.validateCounter(10, limit)).toBe(true)
  expect(f.validateCounter(5, limit)).toBe(true)
  expect(f.validateCounter(8, limit)).toBe(true)
  expect(f.validateCounter(3, limit)).toBe(true)
})

test("rejects counters behind window", () => {
  const f = new Replay.ReplayFilter()
  const limit = Number.MAX_SAFE_INTEGER

  // Advance window far ahead
  expect(f.validateCounter(10000, limit)).toBe(true)

  // Counter 0 should be behind the window (window size = 8128)
  expect(f.validateCounter(0, limit)).toBe(false)

  // But a counter within the window should still be valid
  expect(f.validateCounter(10000 - 100, limit)).toBe(true)
})

test("rejects at limit", () => {
  const f = new Replay.ReplayFilter()
  expect(f.validateCounter(100, 100)).toBe(false)
  expect(f.validateCounter(99, 100)).toBe(true)
})

test("reset clears state", () => {
  const f = new Replay.ReplayFilter()
  const limit = Number.MAX_SAFE_INTEGER
  f.validateCounter(5, limit)
  f.reset()
  expect(f.validateCounter(5, limit)).toBe(true)
})

test("large counter jumps", () => {
  const f = new Replay.ReplayFilter()
  const limit = Number.MAX_SAFE_INTEGER
  expect(f.validateCounter(0, limit)).toBe(true)
  expect(f.validateCounter(20000, limit)).toBe(true)
  expect(f.validateCounter(20001, limit)).toBe(true)
  expect(f.validateCounter(20000, limit)).toBe(false)
  // Old counter should be rejected (outside window)
  expect(f.validateCounter(0, limit)).toBe(false)
})
