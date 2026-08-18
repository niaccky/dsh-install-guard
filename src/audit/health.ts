import { loadCached, METADATA_TTL_MS, type TtlCache } from '../cache.js'
import type { ResolvedPackage } from './registry.js'

const DEFAULT_DOWNLOADS_URL = 'https://api.npmjs.org/downloads/point/last-week'
const POPULAR_PACKAGES = [
  'axios',
  'chalk',
  'commander',
  'dotenv',
  'express',
  'lodash',
  'next',
  'react',
  'react-dom',
  'typescript',
  'vite',
  'vue',
  'webpack',
] as const

export type HealthIssueKind = 'deprecated' | 'no-maintainers' | 'young-and-unpopular' | 'typosquatting'

export interface HealthIssue {
  kind: HealthIssueKind
  message: string
}

export interface PackageHealth {
  weeklyDownloads: number
  ageDays?: number
  maintainerCount?: number
  similarPopularPackage?: string
  issues: HealthIssue[]
}

export interface HealthThresholds {
  minWeeklyDownloads: number
  minPackageAgeDays: number
  typosquatMaxDistance: number
}

export interface HealthOptions {
  fetch?: typeof globalThis.fetch
  downloadsUrl?: string
  signal?: AbortSignal
  cache?: TtlCache
  metadataTtlMs?: number
  onCacheFallback?: (message: string) => void
}

export async function queryWeeklyDownloads(
  pkg: ResolvedPackage,
  options: HealthOptions = {},
): Promise<number> {
  const baseUrl = (options.downloadsUrl ?? DEFAULT_DOWNLOADS_URL).replace(/\/+$/, '')
  const url = `${baseUrl}/${encodeURIComponent(pkg.name)}`
  return loadCached({
    cache: options.cache,
    key: `downloads:${url}`,
    ttlMs: options.metadataTtlMs ?? METADATA_TTL_MS,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    staleMessage: `npm 下载量缓存已过期，离线沿用 ${pkg.name} 的旧数据`,
    ...(options.onCacheFallback === undefined ? {} : { onStale: options.onCacheFallback }),
    load: async () => {
      const response = await (options.fetch ?? globalThis.fetch)(url, {
        headers: { accept: 'application/json' },
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      })
      if (!response.ok) {
        throw new Error(`npm downloads returned ${response.status} for ${pkg.name}`)
      }
      const body: unknown = await response.json()
      if (!isRecord(body) || !isCount(body.downloads)) {
        throw new Error(`npm downloads returned invalid data for ${pkg.name}`)
      }
      return body.downloads
    },
  })
}

export function assessPackageHealth(
  pkg: ResolvedPackage,
  weeklyDownloads: number,
  thresholds: HealthThresholds,
  now = Date.now(),
): PackageHealth {
  const ageDays = packageAgeDays(pkg.metadata.createdAt, now)
  const similarPopularPackage = weeklyDownloads < thresholds.minWeeklyDownloads
    ? closestPopularPackage(pkg.name, thresholds.typosquatMaxDistance)
    : undefined
  const issues: HealthIssue[] = []

  if (pkg.metadata.deprecated !== undefined) {
    issues.push({
      kind: 'deprecated',
      message: `版本已弃用：${pkg.metadata.deprecated}`,
    })
  }
  if (pkg.metadata.maintainers === 0) {
    issues.push({
      kind: 'no-maintainers',
      message: 'registry 未列出维护者',
    })
  }
  if (
    ageDays !== undefined
    && ageDays < thresholds.minPackageAgeDays
    && weeklyDownloads < thresholds.minWeeklyDownloads
  ) {
    issues.push({
      kind: 'young-and-unpopular',
      message: `仅发布 ${Math.floor(ageDays)} 天且周下载量只有 ${weeklyDownloads}`,
    })
  }
  if (similarPopularPackage !== undefined) {
    issues.push({
      kind: 'typosquatting',
      message: `低下载量包名与流行包 ${similarPopularPackage} 高度相似，疑似 typosquatting`,
    })
  }

  return {
    weeklyDownloads,
    ...(ageDays === undefined ? {} : { ageDays }),
    ...(pkg.metadata.maintainers === undefined ? {} : { maintainerCount: pkg.metadata.maintainers }),
    ...(similarPopularPackage === undefined ? {} : { similarPopularPackage }),
    issues,
  }
}

function packageAgeDays(createdAt: string | undefined, now: number): number | undefined {
  if (createdAt === undefined) return undefined
  const created = Date.parse(createdAt)
  if (!Number.isFinite(created)) return undefined
  return Math.max(0, (now - created) / (24 * 60 * 60 * 1000))
}

function closestPopularPackage(name: string, maxDistance: number): string | undefined {
  if (name.startsWith('@') || maxDistance < 1) return undefined
  let closest: string | undefined
  let closestDistance = Number.POSITIVE_INFINITY
  for (const popular of POPULAR_PACKAGES) {
    if (popular === name.toLowerCase()) continue
    const distance = damerauLevenshtein(name.toLowerCase(), popular)
    if (distance <= maxDistance && distance < closestDistance) {
      closest = popular
      closestDistance = distance
    }
  }
  return closest
}

/** Optimal-string-alignment distance, including adjacent transpositions. */
function damerauLevenshtein(left: string, right: string): number {
  const rows = left.length + 1
  const columns = right.length + 1
  const distance = Array.from({ length: rows }, () => Array<number>(columns).fill(0))
  for (let row = 0; row < rows; row += 1) distance[row]![0] = row
  for (let column = 0; column < columns; column += 1) distance[0]![column] = column

  for (let row = 1; row < rows; row += 1) {
    for (let column = 1; column < columns; column += 1) {
      const substitutionCost = left[row - 1] === right[column - 1] ? 0 : 1
      distance[row]![column] = Math.min(
        distance[row - 1]![column]! + 1,
        distance[row]![column - 1]! + 1,
        distance[row - 1]![column - 1]! + substitutionCost,
      )
      if (
        row > 1
        && column > 1
        && left[row - 1] === right[column - 2]
        && left[row - 2] === right[column - 1]
      ) {
        distance[row]![column] = Math.min(
          distance[row]![column]!,
          distance[row - 2]![column - 2]! + substitutionCost,
        )
      }
    }
  }
  return distance[left.length]![right.length]!
}

function isCount(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
