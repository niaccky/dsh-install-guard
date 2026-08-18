export const VULNERABILITY_TTL_MS = 24 * 60 * 60 * 1000
export const METADATA_TTL_MS = 7 * 24 * 60 * 60 * 1000

export interface TtlCacheOptions {
  now?: (() => number) | undefined
}

interface CacheEntry<T> {
  value: T
  expiresAt: number
}

/** Small injectable-clock TTL cache shared by the package audit data sources. */
export class TtlCache {
  readonly #entries = new Map<string, CacheEntry<unknown>>()
  readonly #now: () => number

  constructor(options: TtlCacheOptions = {}) {
    this.#now = options.now ?? Date.now
  }

  get<T>(key: string): T | undefined {
    const entry = this.#entries.get(key)
    if (entry === undefined || entry.expiresAt <= this.#now()) return undefined
    return entry.value as T
  }

  getStale<T>(key: string): T | undefined {
    return this.#entries.get(key)?.value as T | undefined
  }

  set<T>(key: string, value: T, ttlMs: number): void {
    if (!Number.isFinite(ttlMs) || ttlMs < 0) {
      throw new RangeError('cache TTL must be a finite non-negative number')
    }
    this.#entries.set(key, { value, expiresAt: this.#now() + ttlMs })
  }

  delete(key: string): boolean {
    return this.#entries.delete(key)
  }

  clear(): void {
    this.#entries.clear()
  }
}

interface CachedLoadOptions<T> {
  cache?: TtlCache | undefined
  key: string
  ttlMs: number
  signal?: AbortSignal | undefined
  load: () => Promise<T>
  onStale?: ((message: string) => void) | undefined
  staleMessage: string
}

/**
 * Return a fresh cache entry, otherwise refresh it. An expired entry is only
 * reused when the refresh fails, so normal TTL behavior and offline resilience
 * remain independently testable.
 */
export async function loadCached<T>(options: CachedLoadOptions<T>): Promise<T> {
  throwIfAborted(options.signal)
  const cached = options.cache?.get<T>(options.key)
  if (cached !== undefined) return cached

  try {
    const value = await options.load()
    options.cache?.set(options.key, value, options.ttlMs)
    return value
  } catch (error: unknown) {
    if (options.signal?.aborted === true || isAbortError(error)) throw error
    const stale = options.cache?.getStale<T>(options.key)
    if (stale === undefined) throw error
    options.onStale?.(options.staleMessage)
    return stale
  }
}

function isAbortError(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError'
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted !== true) return
  throw signal.reason instanceof Error ? signal.reason : new DOMException('The operation was aborted', 'AbortError')
}
