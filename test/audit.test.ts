import { describe, expect, it, vi } from 'vitest'
import { auditPackages, cvssV3BaseScore, resolvePackageVersion } from '../src/audit/index.js'

describe('registry resolution', () => {
  it('resolves ranges and dist-tags to exact published versions', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse({
      'dist-tags': { latest: '2.0.0', next: '3.0.0-beta.1' },
      versions: {
        '1.0.0': {},
        '1.9.0': {},
        '2.0.0': {},
        '3.0.0-beta.1': {},
      },
    }))

    await expect(resolvePackageVersion(
      { name: '@scope/pkg', requested: '^1.0.0', raw: '@scope/pkg@^1.0.0' },
      { fetch: fetchMock },
    )).resolves.toMatchObject({ version: '1.9.0' })
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe('https://registry.npmjs.org/%40scope%2Fpkg')

    await expect(resolvePackageVersion(
      { name: '@scope/pkg', requested: 'next', raw: '@scope/pkg@next' },
      { fetch: fetchMock },
    )).resolves.toMatchObject({ version: '3.0.0-beta.1' })
  })

  it('rejects invalid and unpublished selections', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => jsonResponse({
      'dist-tags': { latest: '1.0.0' },
      versions: { '1.0.0': {} },
    }))

    await expect(resolvePackageVersion(
      { name: 'demo', requested: '^9', raw: 'demo@^9' },
      { fetch: fetchMock },
    )).rejects.toThrow('could not resolve demo@^9')
  })
})

describe('OSV audit decisions', () => {
  it('denies HIGH/CRITICAL findings and queries OSV with the exact version', async () => {
    const requestBodies: unknown[] = []
    const fetchMock = vi.fn<typeof fetch>(async (input, init) => {
      if (String(input).includes('registry.npmjs.org')) {
        return jsonResponse({
          'dist-tags': { latest: '4.17.21' },
          versions: { '4.17.20': {}, '4.17.21': {} },
        })
      }
      requestBodies.push(JSON.parse(String(init?.body)))
      return jsonResponse({
        vulns: [{
          id: 'GHSA-test-high',
          aliases: ['CVE-2026-1234'],
          summary: 'Prototype pollution',
          severity: [{
            type: 'CVSS_V3',
            score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          }],
        }],
      })
    })

    const report = await auditPackages(
      [{ name: 'lodash', requested: '^4.17.0', raw: 'lodash@^4.17.0' }],
      { fetch: fetchMock },
    )

    expect(requestBodies).toEqual([{
      package: { name: 'lodash', ecosystem: 'npm' },
      version: '4.17.21',
    }])
    expect(report.verdict).toBe('deny')
    expect(report.message).toContain('CVE-2026-1234 [CRITICAL，CVSS 9.8]')
  })

  it('asks for lower or unknown severity findings', async () => {
    const fetchMock = sequentialAuditFetch({
      vulns: [{
        id: 'GHSA-medium',
        summary: 'A moderate issue',
        database_specific: { severity: 'MODERATE' },
      }],
    })

    const report = await auditPackages([{ name: 'demo', raw: 'demo' }], { fetch: fetchMock })
    expect(report.verdict).toBe('ask')
    expect(report.packages[0]?.vulnerabilities[0]?.severity).toBe('medium')
  })

  it('allows a clean exact version and deduplicates identical requests', async () => {
    const fetchMock = sequentialAuditFetch({})
    const request = { name: 'react', requested: '19.1.1', raw: 'react@19.1.1' }

    const report = await auditPackages([request, request], { fetch: fetchMock })
    expect(report.verdict).toBe('allow')
    expect(report.message).toContain('react@19.1.1')
    expect(fetchMock).toHaveBeenCalledTimes(4)
  })

  it('fails open by default and asks when failClosed is enabled', async () => {
    const fetchMock = vi.fn<typeof fetch>(async () => new Response('unavailable', { status: 503 }))
    const request = [{ name: 'demo', raw: 'demo' }]
    const report = await auditPackages(request, { fetch: fetchMock })
    const strictReport = await auditPackages(request, { fetch: fetchMock, failClosed: true })

    expect(report.verdict).toBe('allow')
    expect(report.message).toContain('fail-open')
    expect(strictReport.verdict).toBe('ask')
    expect(strictReport.message).toContain('failClosed')
  })

  it('propagates cancellation instead of converting it to an approval prompt', async () => {
    const controller = new AbortController()
    controller.abort(new DOMException('cancelled', 'AbortError'))

    await expect(auditPackages(
      [{ name: 'demo', raw: 'demo' }],
      { signal: controller.signal },
    )).rejects.toMatchObject({ name: 'AbortError' })
  })
})

describe('license, size and health decisions', () => {
  it('asks for blocked licenses but accepts an SPDX OR alternative', async () => {
    const blocked = await auditPackages(
      [{ name: 'copyleft', raw: 'copyleft' }],
      { fetch: completeAuditFetch({ license: 'GPL-3.0-only' }) },
    )
    const alternative = await auditPackages(
      [{ name: 'dual-license', raw: 'dual-license' }],
      { fetch: completeAuditFetch({ license: 'MIT OR GPL-3.0-only' }) },
    )

    expect(blocked.verdict).toBe('ask')
    expect(blocked.packages[0]?.license).toMatchObject({
      status: 'blocked',
      blockedLicenses: ['GPL-3.0-only'],
    })
    expect(alternative.verdict).toBe('allow')
  })

  it('asks for a large non-tree-shakeable bundle', async () => {
    const report = await auditPackages(
      [{ name: 'large-package', raw: 'large-package' }],
      {
        fetch: completeAuditFetch({
          size: { size: 100_000, gzip: 50_000, hasJSModule: false, hasSideEffects: true },
        }),
      },
    )

    expect(report.verdict).toBe('ask')
    expect(report.message).toContain('不能确认可安全 tree-shake')
  })

  it('does not flag an oversized tree-shakeable bundle', async () => {
    const report = await auditPackages(
      [{ name: 'modular-package', raw: 'modular-package' }],
      {
        fetch: completeAuditFetch({
          size: { size: 100_000, gzip: 50_000, hasJSModule: true, hasSideEffects: false },
        }),
      },
    )

    expect(report.verdict).toBe('allow')
    expect(report.packages[0]?.bundleSize?.treeShakeable).toBe(true)
    expect(report.message).toContain('实际体积取决于用法')
  })

  it('detects low-download typosquatting candidates', async () => {
    const report = await auditPackages(
      [{ name: 'raect', raw: 'raect' }],
      { fetch: completeAuditFetch({ weeklyDownloads: 9 }) },
    )

    expect(report.verdict).toBe('ask')
    expect(report.packages[0]?.health?.similarPopularPackage).toBe('react')
    expect(report.message).toContain('疑似 typosquatting')
  })

  it('asks for a young low-download package and allows policy threshold changes', async () => {
    const young = await auditPackages(
      [{ name: 'brand-new-package', raw: 'brand-new-package' }],
      {
        fetch: completeAuditFetch({
          createdAt: '2026-08-18T00:00:00.000Z',
          weeklyDownloads: 1,
        }),
        now: () => Date.parse('2026-08-19T00:00:00.000Z'),
      },
    )
    const lowVulnerability = await auditPackages(
      [{ name: 'low-risk', raw: 'low-risk' }],
      {
        fetch: completeAuditFetch({
          osv: {
            vulns: [{
              id: 'GHSA-low',
              summary: 'Low risk',
              database_specific: { severity: 'LOW' },
            }],
          },
        }),
        askSeverity: 'medium',
      },
    )

    expect(young.verdict).toBe('ask')
    expect(young.packages[0]?.health?.issues[0]?.kind).toBe('young-and-unpopular')
    expect(lowVulnerability.verdict).toBe('allow')
  })

  it('skips all checks for exact and scoped wildcard allowlist entries', async () => {
    const fetchMock = vi.fn<typeof fetch>()
    const report = await auditPackages([
      { name: 'trusted', raw: 'trusted' },
      { name: '@internal/pkg', raw: '@internal/pkg' },
    ], {
      fetch: fetchMock,
      allowPackages: ['trusted', '@internal/*'],
    })

    expect(report.verdict).toBe('allow')
    expect(report.packages.every(pkg => pkg.whitelisted === true)).toBe(true)
    expect(fetchMock).not.toHaveBeenCalled()
  })
})

describe('CVSS normalization', () => {
  it('computes the CVSS v3 base score and rejects unsupported vectors', () => {
    expect(cvssV3BaseScore('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H')).toBe(9.8)
    expect(cvssV3BaseScore('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H')).toBeUndefined()
  })
})

function sequentialAuditFetch(osvBody: unknown): ReturnType<typeof vi.fn<typeof fetch>> {
  return vi.fn<typeof fetch>(async (input) => {
    if (String(input).includes('registry.npmjs.org')) {
      return jsonResponse({
        'dist-tags': { latest: '19.1.1' },
        versions: { '19.1.1': { license: 'MIT' } },
        time: { created: '2013-05-24T00:00:00.000Z' },
        maintainers: [{ name: 'maintainer' }],
      })
    }
    if (String(input).includes('api.osv.dev')) return jsonResponse(osvBody)
    if (String(input).includes('bundlephobia.com')) {
      return jsonResponse({ size: 10_000, gzip: 5_000, hasJSModule: true, hasSideEffects: false })
    }
    return jsonResponse({ downloads: 1_000_000 })
  })
}

interface CompleteAuditOptions {
  license?: string
  createdAt?: string
  weeklyDownloads?: number
  size?: Record<string, unknown>
  osv?: unknown
}

function completeAuditFetch(options: CompleteAuditOptions = {}): ReturnType<typeof vi.fn<typeof fetch>> {
  return vi.fn<typeof fetch>(async (input) => {
    const url = String(input)
    if (url.includes('registry.npmjs.org')) {
      return jsonResponse({
        'dist-tags': { latest: '1.0.0' },
        versions: { '1.0.0': { license: options.license ?? 'MIT' } },
        time: { created: options.createdAt ?? '2020-01-01T00:00:00.000Z' },
        maintainers: [{ name: 'maintainer' }],
      })
    }
    if (url.includes('api.osv.dev')) return jsonResponse(options.osv ?? {})
    if (url.includes('bundlephobia.com')) {
      return jsonResponse(options.size ?? {
        size: 10_000,
        gzip: 5_000,
        hasJSModule: true,
        hasSideEffects: false,
      })
    }
    return jsonResponse({ downloads: options.weeklyDownloads ?? 1_000_000 })
  })
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}
