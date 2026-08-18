import { loadCached, VULNERABILITY_TTL_MS, type TtlCache } from '../cache.js'
import type { ResolvedPackage } from './registry.js'

const DEFAULT_OSV_URL = 'https://api.osv.dev/v1/query'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown'

export interface Vulnerability {
  id: string
  aliases: string[]
  summary: string
  severity: Severity
  score?: number
}

export interface OsvOptions {
  fetch?: typeof globalThis.fetch
  osvUrl?: string
  signal?: AbortSignal
  cache?: TtlCache
  vulnerabilityTtlMs?: number
  onCacheFallback?: (message: string) => void
}

interface OsvVulnerability {
  id?: unknown
  aliases?: unknown
  summary?: unknown
  details?: unknown
  severity?: unknown
  database_specific?: unknown
  affected?: unknown
}

/** Query OSV for one exact npm package version and normalize advisory severity. */
export async function queryOsv(
  pkg: ResolvedPackage,
  options: OsvOptions = {},
): Promise<Vulnerability[]> {
  throwIfAborted(options.signal)
  const fetchImpl = options.fetch ?? globalThis.fetch
  const endpoint = options.osvUrl ?? DEFAULT_OSV_URL
  return loadCached({
    cache: options.cache,
    key: `osv:${endpoint}:${pkg.name}@${pkg.version}`,
    ttlMs: options.vulnerabilityTtlMs ?? VULNERABILITY_TTL_MS,
    ...(options.signal === undefined ? {} : { signal: options.signal }),
    staleMessage: `OSV 缓存已过期，离线沿用 ${pkg.name}@${pkg.version} 的旧漏洞数据`,
    ...(options.onCacheFallback === undefined ? {} : { onStale: options.onCacheFallback }),
    load: async () => {
      const response = await fetchImpl(endpoint, {
        method: 'POST',
        headers: {
          accept: 'application/json',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          package: { name: pkg.name, ecosystem: 'npm' },
          version: pkg.version,
        }),
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      })
      if (!response.ok) throw new Error(`OSV returned ${response.status} for ${pkg.name}@${pkg.version}`)

      const body: unknown = await response.json()
      if (!isRecord(body)) throw new Error(`OSV returned an invalid document for ${pkg.name}@${pkg.version}`)
      if (body.vulns === undefined) return []
      if (!Array.isArray(body.vulns)) {
        throw new Error(`OSV returned an invalid vulnerability list for ${pkg.name}@${pkg.version}`)
      }
      return body.vulns
        .filter((item): item is OsvVulnerability => isRecord(item))
        .map(normalizeVulnerability)
        .sort((left, right) => severityRank(right.severity) - severityRank(left.severity))
    },
  })
}

function normalizeVulnerability(raw: OsvVulnerability): Vulnerability {
  const scores = extractScores(raw.severity)
  const explicitSeverities = [
    severityFromRecord(raw.database_specific),
    ...affectedSeverities(raw.affected),
  ].filter((item): item is Severity => item !== undefined)
  const scoredSeverities = scores.map(severityFromScore)
  const severity = [...explicitSeverities, ...scoredSeverities]
    .reduce<Severity>((highest, candidate) => (
      severityRank(candidate) > severityRank(highest) ? candidate : highest
    ), 'unknown')
  const score = scores.length === 0 ? undefined : Math.max(...scores)

  return {
    id: typeof raw.id === 'string' ? raw.id : 'UNKNOWN',
    aliases: Array.isArray(raw.aliases)
      ? raw.aliases.filter((alias): alias is string => typeof alias === 'string')
      : [],
    summary: typeof raw.summary === 'string'
      ? raw.summary
      : typeof raw.details === 'string'
        ? firstLine(raw.details)
        : 'No summary provided by OSV',
    severity,
    ...(score === undefined ? {} : { score }),
  }
}

function affectedSeverities(value: unknown): Severity[] {
  if (!Array.isArray(value)) return []
  return value.flatMap((affected) => {
    if (!isRecord(affected)) return []
    return [
      severityFromRecord(affected.database_specific),
      severityFromRecord(affected.ecosystem_specific),
    ].filter((item): item is Severity => item !== undefined)
  })
}

function severityFromRecord(value: unknown): Severity | undefined {
  if (!isRecord(value)) return undefined
  const candidate = value.severity
  if (typeof candidate !== 'string') return undefined
  switch (candidate.toUpperCase()) {
    case 'CRITICAL': return 'critical'
    case 'HIGH': return 'high'
    case 'MEDIUM':
    case 'MODERATE': return 'medium'
    case 'LOW': return 'low'
    default: return undefined
  }
}

function extractScores(value: unknown): number[] {
  if (!Array.isArray(value)) return []
  return value.flatMap((entry) => {
    if (!isRecord(entry) || typeof entry.score !== 'string') return []
    const numeric = Number(entry.score)
    if (Number.isFinite(numeric) && numeric >= 0 && numeric <= 10) return [numeric]
    const cvss = cvssV3BaseScore(entry.score)
    return cvss === undefined ? [] : [cvss]
  })
}

/** Compute the CVSS v3.0/v3.1 base score needed by OSV's vector-form scores. */
export function cvssV3BaseScore(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector)) return undefined
  const metrics = Object.fromEntries(
    vector.split('/').slice(1).map((part) => part.split(':', 2) as [string, string]),
  )
  const scope = metrics.S
  const av = metric(metrics.AV, { N: 0.85, A: 0.62, L: 0.55, P: 0.2 })
  const ac = metric(metrics.AC, { L: 0.77, H: 0.44 })
  const pr = scope === 'C'
    ? metric(metrics.PR, { N: 0.85, L: 0.68, H: 0.5 })
    : metric(metrics.PR, { N: 0.85, L: 0.62, H: 0.27 })
  const ui = metric(metrics.UI, { N: 0.85, R: 0.62 })
  const confidentiality = metric(metrics.C, { H: 0.56, L: 0.22, N: 0 })
  const integrity = metric(metrics.I, { H: 0.56, L: 0.22, N: 0 })
  const availability = metric(metrics.A, { H: 0.56, L: 0.22, N: 0 })
  if (
    (scope !== 'U' && scope !== 'C')
    || av === undefined
    || ac === undefined
    || pr === undefined
    || ui === undefined
    || confidentiality === undefined
    || integrity === undefined
    || availability === undefined
  ) {
    return undefined
  }

  const impactSubScore = 1 - (
    (1 - confidentiality)
    * (1 - integrity)
    * (1 - availability)
  )
  const impact = scope === 'U'
    ? 6.42 * impactSubScore
    : 7.52 * (impactSubScore - 0.029) - 3.25 * ((impactSubScore - 0.02) ** 15)
  if (impact <= 0) return 0

  const exploitability = 8.22 * av * ac * pr * ui
  const base = scope === 'U'
    ? Math.min(impact + exploitability, 10)
    : Math.min(1.08 * (impact + exploitability), 10)
  return roundUp(base)
}

export function severityFromScore(score: number): Severity {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'unknown'
}

export function severityRank(severity: Severity): number {
  switch (severity) {
    case 'critical': return 4
    case 'high': return 3
    case 'medium': return 2
    case 'low': return 1
    case 'unknown': return 0
  }
}

function metric(
  value: string | undefined,
  values: Readonly<Record<string, number>>,
): number | undefined {
  return value === undefined ? undefined : values[value]
}

function roundUp(score: number): number {
  return Math.ceil((score - Number.EPSILON) * 10) / 10
}

function firstLine(value: string): string {
  return value.split(/\r?\n/, 1)[0]?.trim() || 'No summary provided by OSV'
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function throwIfAborted(signal: AbortSignal | undefined): void {
  if (signal?.aborted !== true) return
  throw signal.reason instanceof Error ? signal.reason : new DOMException('The operation was aborted', 'AbortError')
}
