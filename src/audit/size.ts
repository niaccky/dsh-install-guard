import { loadCached, METADATA_TTL_MS, type TtlCache } from '../cache.js'
import type { ResolvedPackage } from './registry.js'

const DEFAULT_BUNDLEPHOBIA_URL = 'https://bundlephobia.com/api/size'

export interface BundleSize {
  size: number
  gzip: number
  hasJSModule: boolean
  hasSideEffects: boolean
  treeShakeable: boolean
}

export interface SizeOptions {
  fetch?: typeof globalThis.fetch
  bundlephobiaUrl?: string
  signal?: AbortSignal
  cache?: TtlCache
  metadataTtlMs?: number
  onCacheFallback?: (message: string) => void
}

/** Fetch Bundlephobia's full-package estimate and retain tree-shaking signals. */
export async function queryBundleSize(
  pkg: ResolvedPackage,
  options: SizeOptions = {},
): Promise<BundleSize> {
  const endpoint = options.bundlephobiaUrl ?? DEFAULT_BUNDLEPHOBIA_URL
  const url = new URL(endpoint)
  url.searchParams.set('package', `${pkg.name}@${pkg.version}`)

  return loadCached({
    cache: options.cache,
    key: `bundle:${url.href}`,
    ttlMs: options.metadataTtlMs ?? METADATA_TTL_MS,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    staleMessage: `Bundlephobia 缓存已过期，离线沿用 ${pkg.name}@${pkg.version} 的旧体积数据`,
    ...(options.onCacheFallback === undefined ? {} : { onStale: options.onCacheFallback }),
    load: async () => {
      const response = await (options.fetch ?? globalThis.fetch)(url, {
        headers: { accept: 'application/json' },
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      })
      if (!response.ok) {
        throw new Error(`Bundlephobia returned ${response.status} for ${pkg.name}@${pkg.version}`)
      }

      const body: unknown = await response.json()
      if (!isRecord(body) || !isByteCount(body.size) || !isByteCount(body.gzip)) {
        throw new Error(`Bundlephobia returned invalid size data for ${pkg.name}@${pkg.version}`)
      }
      const hasJSModule = body.hasJSModule === true
      const hasSideEffects = body.hasSideEffects !== false
      return {
        size: body.size,
        gzip: body.gzip,
        hasJSModule,
        hasSideEffects,
        treeShakeable: hasJSModule && !hasSideEffects,
      }
    },
  })
}

function isByteCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
