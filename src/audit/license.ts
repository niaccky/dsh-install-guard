export type LicenseStatus = 'allowed' | 'blocked' | 'missing'

export interface LicenseAssessment {
  license?: string
  status: LicenseStatus
  blockedLicenses: string[]
}

/**
 * Evaluate common SPDX `OR`/`AND` expressions. A package remains usable when
 * at least one OR branch avoids every blocked license.
 */
export function assessLicense(
  license: string | undefined,
  blockedLicenses: readonly string[],
): LicenseAssessment {
  if (license === undefined || license.trim() === '') {
    return { status: 'missing', blockedLicenses: [] }
  }

  const alternatives = license
    .replace(/[()]/g, ' ')
    .split(/\s+OR\s+/i)
    .map(branch => branch.trim())
    .filter(Boolean)
  const matched = new Set<string>()
  const everyAlternativeBlocked = alternatives.length > 0 && alternatives.every((branch) => {
    const licenses = branch
      .split(/\s+AND\s+/i)
      .map(part => part.split(/\s+WITH\s+/i, 1)[0]?.trim())
      .filter((part): part is string => part !== undefined && part !== '')
    return licenses.some(candidate => blockedLicenses.some((blocked) => {
      if (!matchesBlockedLicense(candidate, blocked)) return false
      matched.add(candidate)
      return true
    }))
  })

  return {
    license,
    status: everyAlternativeBlocked ? 'blocked' : 'allowed',
    blockedLicenses: [...matched],
  }
}

function matchesBlockedLicense(candidate: string, blocked: string): boolean {
  const normalizedCandidate = normalizeLicense(candidate)
  const normalizedBlocked = normalizeLicense(blocked)
  if (normalizedCandidate === normalizedBlocked) return true
  if (normalizedBlocked.endsWith('*')) {
    return normalizedCandidate.startsWith(normalizedBlocked.slice(0, -1))
  }
  return normalizedCandidate.startsWith(`${normalizedBlocked}-`)
}

function normalizeLicense(value: string): string {
  return value
    .trim()
    .toUpperCase()
    .replace(/\+$/, '')
    .replace(/-(?:ONLY|OR-LATER)$/, '')
}
