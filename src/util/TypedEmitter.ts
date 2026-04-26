import * as NEvents from "node:events"

export interface TypedEmitter<E extends Record<string, unknown[]>> {
  on<K extends keyof E>(event: K, listener: (...args: E[K]) => void): this
  off<K extends keyof E>(event: K, listener: (...args: E[K]) => void): this
  once<K extends keyof E>(event: K, listener: (...args: E[K]) => void): this
  emit<K extends keyof E>(event: K, ...args: E[K]): boolean
  removeAllListeners(): this
}

export function make<E extends Record<string, unknown[]>>(): TypedEmitter<E> {
  return new NEvents.EventEmitter() as unknown as TypedEmitter<E>
}
