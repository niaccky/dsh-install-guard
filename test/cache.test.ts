import { describe, expect, it, vi } from 'vitest'
import { auditPackages } from '../src/audit/index.js'
import {
  METADATA_TTL_MS,
  TtlCache,
  VULNERABILITY_TTL_MS,
} from '../src/cache.js'

describe('TTL cache', () => {
  it('expires entries at the exact TTL while retaining stale fallback data', () => {
    let now = 1_000
    const cache = new TtlCache({ now: () => now })
    cache.set('key', { safe: true }, 100)

    expect(cache.get('key')).toEqual({ safe: true })
    now = 1_099
    expect(cache.get('key')).toEqual({ safe: true })
    now = 1_100
    expect(cache.get('key')).toBeUndefined()
    expect(cache.getStale('key')).toEqual({ safe: true })
  })

  it('uses 24-hour vulnerability and 7-day metadata TTLs', async () => {
    let now = 0
    const cache = new TtlCache({ now: () => now })
    const fetchMock = healthyFetch()
    const request = [{ name: 'demo', raw: 'demo' }]

    await auditPackages(request, { cache, fetch: fetchMock, now: () => now })
    await auditPackages(request, { cache, fetch: fetchMock, now: () => now })
    expect(endpointCalls(fetchMock)).toEqual({
      registry: 1,
      osv: 1,
      size: 1,
      downloads: 1,
    })

    now = VULNERABILITY_TTL_MS
    await auditPackages(request, { cache, fetch: fetchMock, now: () => now })
    expect(endpointCalls(fetchMock)).toEqual({
      registry: 1,
      osv: 2,
      size: 1,
      downloads: 1,
    })

    now = METADATA_TTL_MS
    await auditPackages(request, { cache, fetch: fetchMock, now: () => now })
    expect(endpointCalls(fetchMock)).toEqual({
      registry: 2,
      osv: 3,
      size: 2,
      downloads: 2,
    })
  })

  it('reuses expired data when offline and makes the degraded state explicit', async () => {
    let now = 0
    let offline = false
    const cache = new TtlCache({ now: () => now })
    const fetchMock = healthyFetch(() => offline)
    const request = [{ name: 'demo', raw: 'demo' }]

    await auditPackages(request, { cache, fetch: fetchMock, now: () => now })
    now = METADATA_TTL_MS + 1
    offline = true
    const report = await auditPackages(request, { cache, fetch: fetchMock, now: () => now })
    const strictReport = await auditPackages(request, {
      cache,
      fetch: fetchMock,
      now: () => now,
      failClosed: true,
    })

    expect(report.verdict).toBe('allow')
    expect(report.packages[0]?.errors).toEqual([])
    expect(report.packages[0]?.warnings).toHaveLength(4)
    expect(report.message).toContain('fail-open')
    expect(report.message).toContain('缓存已过期')
    expect(strictReport.verdict).toBe('ask')
    expect(strictReport.message).toContain('failClosed')
  })
})

function healthyFetch(isOffline: () => boolean = () => false): ReturnType<typeof vi.fn<typeof fetch>> {
  return vi.fn<typeof fetch>(async (input) => {
    if (isOffline()) throw new TypeError('fetch failed')
    const url = String(input)
    if (url.includes('registry.npmjs.org')) {
      return jsonResponse({
        'dist-tags': { latest: '1.0.0' },
        versions: { '1.0.0': { license: 'MIT' } },
        time: { created: '2020-01-01T00:00:00.000Z' },
        maintainers: [{ name: 'maintainer' }],
      })
    }
    if (url.includes('api.osv.dev')) return jsonResponse({})
    if (url.includes('bundlephobia.com')) {
      return jsonResponse({
        size: 10_000,
        gzip: 5_000,
        hasJSModule: true,
        hasSideEffects: false,
      })
    }
    return jsonResponse({ downloads: 1_000_000 })
  })
}

function endpointCalls(fetchMock: ReturnType<typeof vi.fn<typeof fetch>>): Record<string, number> {
  const urls = fetchMock.mock.calls.map(call => String(call[0]))
  return {
    registry: urls.filter(url => url.includes('registry.npmjs.org')).length,
    osv: urls.filter(url => url.includes('api.osv.dev')).length,
    size: urls.filter(url => url.includes('bundlephobia.com')).length,
    downloads: urls.filter(url => url.includes('api.npmjs.org')).length,
  }
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}
