export interface LightweightAlternative {
  /** Registry package to evaluate alongside the original dependency. */
  name: string
  /** Why the alternative can reduce install or bundle cost. */
  reason: string
  /** Compatibility boundary the model must account for before recommending it. */
  caveat: string
}

/**
 * Curated, deliberately small alternatives catalog.
 *
 * Every entry needs a concrete size/maintenance motivation and an explicit
 * migration caveat. This avoids presenting substitutes as drop-in replacements
 * when they implement a narrower API or a different standard.
 */
export const LIGHTWEIGHT_ALTERNATIVES = {
  axios: [{
    name: 'ky',
    reason: '基于标准 Fetch API，浏览器与现代 Node.js 项目的客户端体积通常更小。',
    caveat: '不是 Axios 的直接替换；拦截器、错误对象和请求配置 API 不兼容。',
  }],
  chalk: [{
    name: 'picocolors',
    reason: '仅提供常用终端着色能力，安装和运行时开销更低。',
    caveat: 'API 与 Chalk 不同，且不覆盖复杂样式与颜色检测用法。',
  }],
  lodash: [{
    name: 'lodash-es',
    reason: 'ES module 构建便于 bundler 对按需导入执行 tree-shaking。',
    caveat: '仅适合 ESM/bundler 场景；全量导入仍可能保留大部分体积。',
  }],
  moment: [{
    name: 'dayjs',
    reason: '核心包更小，并提供接近 Moment 的链式日期 API。',
    caveat: '时区、国际化和高级能力通常需要插件，迁移前应核对行为差异。',
  }],
  request: [{
    name: 'undici',
    reason: 'Request 已弃用；Undici 是维护中的现代 Node.js HTTP 客户端。',
    caveat: 'API 不兼容；Node.js 18+ 的简单请求也可直接使用内置 fetch。',
  }],
  uuid: [{
    name: 'nanoid',
    reason: '在只需要紧凑随机标识符时，API 和包体积都更小。',
    caveat: 'Nano ID 不是 RFC UUID；协议或数据库要求 UUID 时不能替换。',
  }],
} as const satisfies Record<string, readonly LightweightAlternative[]>

export function alternativesFor(packageName: string): LightweightAlternative[] {
  const alternatives = (LIGHTWEIGHT_ALTERNATIVES as Record<string, readonly LightweightAlternative[]>)[packageName]
  return alternatives?.map(alternative => ({ ...alternative })) ?? []
}
