import type { InstallRequest } from '../parse.js'
import { TtlCache } from '../cache.js'
import {
  assessPackageHealth,
  queryWeeklyDownloads,
  type HealthOptions,
  type PackageHealth,
} from './health.js'
import { assessLicense, type LicenseAssessment } from './license.js'
import { queryOsv, severityRank, type OsvOptions, type Severity, type Vulnerability } from './osv.js'
import { resolvePackageVersion, type RegistryOptions, type ResolvedPackage } from './registry.js'
import { queryBundleSize, type BundleSize, type SizeOptions } from './size.js'

export type AuditVerdict = 'deny' | 'ask' | 'allow'

export type AuditCheck = 'registry' | 'osv' | 'size' | 'health'

export interface AuditError {
  check: AuditCheck
  message: string
}

export interface PackageAudit {
  requested: InstallRequest
  resolved?: ResolvedPackage
  vulnerabilities: Vulnerability[]
  license?: LicenseAssessment
  bundleSize?: BundleSize
  health?: PackageHealth
  errors: AuditError[]
  warnings: string[]
  whitelisted?: boolean
  /** @deprecated Use `errors` to retain the failed check identity. */
  error?: string
}

export interface AuditReport {
  verdict: AuditVerdict
  packages: PackageAudit[]
  message: string
}

export interface AuditPolicy {
  denySeverity?: Severity
  askSeverity?: Severity
  blockedLicenses?: readonly string[]
  allowPackages?: readonly string[]
  maxBundleSizeKb?: number
  minWeeklyDownloads?: number
  minPackageAgeDays?: number
  typosquatMaxDistance?: number
  failClosed?: boolean
}

export interface AuditOptions extends RegistryOptions, OsvOptions, SizeOptions, HealthOptions, AuditPolicy {
  now?: () => number
}

export const DEFAULT_AUDIT_POLICY = {
  denySeverity: 'high',
  askSeverity: 'unknown',
  blockedLicenses: ['GPL', 'AGPL'],
  allowPackages: [],
  maxBundleSizeKb: 20,
  minWeeklyDownloads: 100,
  minPackageAgeDays: 30,
  typosquatMaxDistance: 1,
  failClosed: false,
} as const satisfies Required<AuditPolicy>

interface NormalizedPolicy {
  denySeverity: Severity
  askSeverity: Severity
  blockedLicenses: readonly string[]
  allowPackages: readonly string[]
  maxBundleSizeKb: number
  minWeeklyDownloads: number
  minPackageAgeDays: number
  typosquatMaxDistance: number
  failClosed: boolean
}

/**
 * Resolve and audit packages concurrently. Security findings use configurable
 * severity thresholds; legal, size and package-health risks ask for approval.
 * Network failures are reported but fail open unless `failClosed` is enabled.
 */
export async function auditPackages(
  requests: readonly InstallRequest[],
  options: AuditOptions = {},
): Promise<AuditReport> {
  const policy = normalizePolicy(options)
  const cache = options.cache ?? new TtlCache({ now: options.now })
  const effectiveOptions: AuditOptions = { ...options, cache }
  const uniqueRequests = deduplicate(requests)
  const packages = await Promise.all(uniqueRequests.map(request => auditPackage(request, effectiveOptions, policy)))
  const verdict = decideVerdict(packages, policy)

  return {
    verdict,
    packages,
    message: formatAuditMessage(verdict, packages, policy),
  }
}

async function auditPackage(
  request: InstallRequest,
  options: AuditOptions,
  policy: NormalizedPolicy,
): Promise<PackageAudit> {
  if (isAllowedPackage(request.name, policy.allowPackages)) {
    return {
      requested: request,
      vulnerabilities: [],
      errors: [],
      warnings: [],
      whitelisted: true,
    }
  }

  const errors: AuditError[] = []
  const warnings: string[] = []
  const onCacheFallback = (message: string): void => {
    warnings.push(message)
    options.onCacheFallback?.(message)
  }
  const checkOptions = { ...options, onCacheFallback }
  let resolved: ResolvedPackage
  try {
    resolved = await resolvePackageVersion(request, checkOptions)
  } catch (error: unknown) {
    throwIfCancellation(error, options.signal)
    const message = errorMessage(error)
    return {
      requested: request,
      vulnerabilities: [],
      errors: [{ check: 'registry', message }],
      warnings,
      error: message,
    }
  }

  const license = assessLicense(resolved.metadata.license, policy.blockedLicenses)
  const [vulnerabilities, bundleSize, weeklyDownloads] = await Promise.all([
    captureCheck('osv', errors, options.signal, () => queryOsv(resolved, checkOptions)),
    captureCheck('size', errors, options.signal, () => queryBundleSize(resolved, checkOptions)),
    captureCheck('health', errors, options.signal, () => queryWeeklyDownloads(resolved, checkOptions)),
  ])
  const health = weeklyDownloads === undefined
    ? undefined
    : assessPackageHealth(resolved, weeklyDownloads, {
      minWeeklyDownloads: policy.minWeeklyDownloads,
      minPackageAgeDays: policy.minPackageAgeDays,
      typosquatMaxDistance: policy.typosquatMaxDistance,
    }, options.now?.())
  const error = errors.length === 0 ? undefined : errors.map(item => item.message).join('; ')
  return {
    requested: request,
    resolved,
    vulnerabilities: vulnerabilities ?? [],
    license,
    ...(bundleSize === undefined ? {} : { bundleSize }),
    ...(health === undefined ? {} : { health }),
    errors,
    warnings,
    ...(error === undefined ? {} : { error }),
  }
}

function deduplicate(requests: readonly InstallRequest[]): InstallRequest[] {
  const seen = new Set<string>()
  return requests.filter((request) => {
    const key = `${request.name}\0${request.requested ?? 'latest'}`
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}

function decideVerdict(packages: readonly PackageAudit[], policy: NormalizedPolicy): AuditVerdict {
  let verdict: AuditVerdict = 'allow'
  for (const pkg of packages) {
    const packageVerdict = decidePackageVerdict(pkg, policy)
    if (packageVerdict === 'deny') return 'deny'
    if (packageVerdict === 'ask') verdict = 'ask'
  }
  return verdict
}

/** Evaluate one package with the same policy semantics as the aggregate audit. */
export function packageAuditVerdict(
  pkg: PackageAudit,
  policy: AuditPolicy = {},
): AuditVerdict {
  return decidePackageVerdict(pkg, normalizePolicy(policy))
}

function decidePackageVerdict(pkg: PackageAudit, policy: NormalizedPolicy): AuditVerdict {
  let verdict: AuditVerdict = 'allow'
  for (const vulnerability of pkg.vulnerabilities) {
    if (severityRank(vulnerability.severity) >= severityRank(policy.denySeverity)) return 'deny'
    if (severityRank(vulnerability.severity) >= severityRank(policy.askSeverity)) verdict = 'ask'
  }
  if (
    pkg.license?.status === 'blocked'
    || pkg.license?.status === 'missing'
    || isOversized(pkg, policy)
    || (pkg.health?.issues.length ?? 0) > 0
    || (policy.failClosed && (pkg.errors.length > 0 || pkg.warnings.length > 0))
  ) {
    verdict = 'ask'
  }
  return verdict
}

function formatAuditMessage(
  verdict: AuditVerdict,
  packages: readonly PackageAudit[],
  policy: NormalizedPolicy,
): string {
  const lines = packages.flatMap(pkg => packageMessages(pkg, policy))
  if (verdict === 'deny') {
    return ['安装已拒绝：漏洞风险达到拒绝阈值。', ...lines].join('\n')
  }
  if (verdict === 'ask') {
    return ['安装需要确认：发现许可证、体积、健康度或审计完整性风险。', ...lines].join('\n')
  }
  const hasDegradedChecks = packages.some(pkg => pkg.errors.length > 0 || pkg.warnings.length > 0)
  const heading = hasDegradedChecks
    ? '网络检查未全部完成，已按 fail-open 默认策略放行。'
    : `未发现达到阈值的依赖风险：${packages.map(packageLabel).join(', ') || '没有可审计的包'}`
  return [heading, ...lines].join('\n')
}

function packageMessages(pkg: PackageAudit, policy: NormalizedPolicy): string[] {
  if (pkg.whitelisted === true) return [`- ${packageLabel(pkg)}：命中包白名单，已跳过检查`]
  const lines = pkg.vulnerabilities.map((vulnerability) => {
    const identifier = vulnerability.aliases.find(alias => alias.startsWith('CVE-')) ?? vulnerability.id
    const score = vulnerability.score === undefined ? '' : `，CVSS ${vulnerability.score.toFixed(1)}`
    return `- ${packageLabel(pkg)}：${identifier} [${vulnerability.severity.toUpperCase()}${score}] — ${vulnerability.summary}`
  })
  if (pkg.license?.status === 'missing') {
    lines.push(`- ${packageLabel(pkg)}：未声明许可证`)
  } else if (pkg.license?.status === 'blocked') {
    lines.push(`- ${packageLabel(pkg)}：许可证 ${pkg.license.license ?? '未知'} 命中黑名单（${pkg.license.blockedLicenses.join(', ')}）`)
  }
  if (pkg.bundleSize !== undefined && pkg.bundleSize.gzip > policy.maxBundleSizeKb * 1000) {
    const size = formatKilobytes(pkg.bundleSize.gzip)
    if (pkg.bundleSize.treeShakeable) {
      lines.push(`- ${packageLabel(pkg)}：gzip ${size} 超过 ${policy.maxBundleSizeKb} KB，但支持 tree-shaking，实际体积取决于用法（未据此拦截）`)
    } else {
      lines.push(`- ${packageLabel(pkg)}：gzip ${size} 超过 ${policy.maxBundleSizeKb} KB，且不能确认可安全 tree-shake`)
    }
  }
  for (const issue of pkg.health?.issues ?? []) {
    lines.push(`- ${packageLabel(pkg)}：${issue.message}`)
  }
  for (const error of pkg.errors) {
    const behavior = policy.failClosed ? '按 failClosed 要求人工确认' : '已 fail-open'
    lines.push(`- ${packageLabel(pkg)}：${error.check} 检查失败（${error.message}，${behavior}）`)
  }
  for (const warning of pkg.warnings) {
    const behavior = policy.failClosed ? '（按 failClosed 要求人工确认）' : ''
    lines.push(`- ${packageLabel(pkg)}：${warning}${behavior}`)
  }
  return lines
}

function packageLabel(pkg: PackageAudit): string {
  return `${pkg.requested.name}@${pkg.resolved?.version ?? pkg.requested.requested ?? 'latest'}`
}

function isOversized(pkg: PackageAudit, policy: NormalizedPolicy): boolean {
  return pkg.bundleSize !== undefined
    && pkg.bundleSize.gzip > policy.maxBundleSizeKb * 1000
    && !pkg.bundleSize.treeShakeable
}

function isAllowedPackage(name: string, allowPackages: readonly string[]): boolean {
  return allowPackages.some((pattern) => {
    if (pattern === '*' || pattern === name) return true
    return pattern.endsWith('/*') && name.startsWith(pattern.slice(0, -1))
  })
}

async function captureCheck<T>(
  check: AuditCheck,
  errors: AuditError[],
  signal: AbortSignal | undefined,
  callback: () => Promise<T>,
): Promise<T | undefined> {
  try {
    return await callback()
  } catch (error: unknown) {
    throwIfCancellation(error, signal)
    errors.push({ check, message: errorMessage(error) })
    return undefined
  }
}

function normalizePolicy(options: AuditPolicy): NormalizedPolicy {
  return {
    denySeverity: options.denySeverity ?? DEFAULT_AUDIT_POLICY.denySeverity,
    askSeverity: options.askSeverity ?? DEFAULT_AUDIT_POLICY.askSeverity,
    blockedLicenses: options.blockedLicenses ?? DEFAULT_AUDIT_POLICY.blockedLicenses,
    allowPackages: options.allowPackages ?? DEFAULT_AUDIT_POLICY.allowPackages,
    maxBundleSizeKb: options.maxBundleSizeKb ?? DEFAULT_AUDIT_POLICY.maxBundleSizeKb,
    minWeeklyDownloads: options.minWeeklyDownloads ?? DEFAULT_AUDIT_POLICY.minWeeklyDownloads,
    minPackageAgeDays: options.minPackageAgeDays ?? DEFAULT_AUDIT_POLICY.minPackageAgeDays,
    typosquatMaxDistance: options.typosquatMaxDistance ?? DEFAULT_AUDIT_POLICY.typosquatMaxDistance,
    failClosed: options.failClosed ?? DEFAULT_AUDIT_POLICY.failClosed,
  }
}

function formatKilobytes(bytes: number): string {
  return `${(bytes / 1000).toFixed(1)} KB`
}

function throwIfCancellation(error: unknown, signal: AbortSignal | undefined): void {
  if (signal?.aborted === true || (error instanceof Error && error.name === 'AbortError')) throw error
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

export type {
  BundleSize,
  HealthOptions,
  InstallRequest,
  LicenseAssessment,
  OsvOptions,
  PackageHealth,
  RegistryOptions,
  ResolvedPackage,
  Severity,
  SizeOptions,
  Vulnerability,
}
export { cvssV3BaseScore, queryOsv, severityFromScore } from './osv.js'
export { assessPackageHealth, queryWeeklyDownloads } from './health.js'
export { assessLicense } from './license.js'
export { resolvePackageVersion } from './registry.js'
export { queryBundleSize } from './size.js'
