import type { Context } from '@deepseek-ai/cordis'
import z from '@deepseek-ai/schemastery'
import type { PreToolDecision } from '@deepseek-ai/dsh-tools'
import { auditPackages } from './audit/index.js'
import { TtlCache } from './cache.js'
import { parseInstallCommand } from './parse.js'
import { createDepCheckTool } from './tool.js'

export const name = 'dsh-install-guard'
export const inject = ['tools']

export interface Config {
  denySeverity?: 'critical' | 'high' | 'medium' | 'low' | 'unknown'
  askSeverity?: 'critical' | 'high' | 'medium' | 'low' | 'unknown'
  blockedLicenses?: string[]
  allowPackages?: string[]
  maxBundleSizeKb?: number
  minWeeklyDownloads?: number
  minPackageAgeDays?: number
  typosquatMaxDistance?: number
  failClosed?: boolean
}

export const Config: z<Config> = z.object({
  denySeverity: z.union(['critical', 'high', 'medium', 'low', 'unknown'])
    .default('high')
    .description('达到该漏洞等级时拒绝安装。'),
  askSeverity: z.union(['critical', 'high', 'medium', 'low', 'unknown'])
    .default('unknown')
    .description('达到该漏洞等级时要求人工确认。'),
  blockedLicenses: z.array(z.string())
    .default(['GPL', 'AGPL'])
    .description('许可证黑名单，支持 SPDX 名称或系列前缀。'),
  allowPackages: z.array(z.string())
    .default([])
    .description('跳过审计的包名白名单；支持 @scope/*。'),
  maxBundleSizeKb: z.natural()
    .default(20)
    .description('非 tree-shakeable 包允许的最大 gzip 体积（KB）。'),
  minWeeklyDownloads: z.natural()
    .default(100)
    .description('健康度检查使用的最低周下载量。'),
  minPackageAgeDays: z.natural()
    .default(30)
    .description('低下载量新包被视为风险前的最短发布天数。'),
  typosquatMaxDistance: z.natural()
    .default(1)
    .description('与流行包名比较时允许的最大编辑距离。'),
  failClosed: z.boolean()
    .default(false)
    .description('网络检查失败时要求人工确认；默认 fail-open。'),
})

export function apply(ctx: Context, config: Config = {}): void {
  const cache = new TtlCache()
  ctx.tools.register(createDepCheckTool({ ...config, cache }))
  ctx.on('tools/pre-execute', async (exec, next): Promise<PreToolDecision> => {
    if (exec.name !== 'bash') return next()

    const command = commandFromArguments(exec.arguments)
    if (command === undefined) return next()

    const installs = parseInstallCommand(command)
    if (installs.length === 0) return next()

    const report = await auditPackages(installs, {
      ...config,
      cache,
      signal: exec.signal,
    })
    if (report.verdict === 'deny') return { kind: 'deny', reason: report.message }
    if (report.verdict === 'ask') return { kind: 'ask', reason: report.message }
    if (report.packages.some(pkg => pkg.errors.length > 0 || pkg.warnings.length > 0)) {
      ctx.logger?.warn(report.message)
    }
    return next()
  })
}

function commandFromArguments(value: unknown): string | undefined {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return undefined
  const command = (value as Record<string, unknown>).command
  return typeof command === 'string' ? command : undefined
}

export { auditPackages, packageAuditVerdict } from './audit/index.js'
export type {
  AuditOptions,
  AuditError,
  AuditPolicy,
  AuditReport,
  AuditVerdict,
  BundleSize,
  LicenseAssessment,
  PackageAudit,
  PackageHealth,
  ResolvedPackage,
  Severity,
  Vulnerability,
} from './audit/index.js'
export {
  METADATA_TTL_MS,
  TtlCache,
  VULNERABILITY_TTL_MS,
} from './cache.js'
export { parseInstallCommand, parsePackageSpec } from './parse.js'
export type { InstallRequest } from './parse.js'
export {
  alternativesFor,
  LIGHTWEIGHT_ALTERNATIVES,
} from './alternatives.js'
export type { LightweightAlternative } from './alternatives.js'
export {
  createDepCheckTool,
  DepCheckError,
  executeDepCheck,
} from './tool.js'
export type {
  DependencySection,
  DepCheckErrorCode,
  DepCheckPackage,
  DepCheckResult,
  DepCheckSkipped,
  DepCheckSource,
} from './tool.js'
