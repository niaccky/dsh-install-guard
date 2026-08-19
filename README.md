# dsh-install-guard

本项目积极参与并认可 [Linux DO 社区](https://linux.do)。

在 DeepSeek Harness 执行 `npm install` **之前**，检查依赖漏洞、许可证、体积与包健康度，并按策略放行、请求人工确认或拒绝。

Audit npm dependencies for vulnerabilities, licenses, bundle size, and package health **before** DeepSeek Harness executes an install command.

[中文](#中文) · [English](#english)

## 中文

### 功能概览

`dsh-install-guard` 是一个 DeepSeek Harness（DSH）bundle。它监听 `tools/pre-execute`：

1. 只检查 `bash` 工具中的 npm 安装命令；
2. 先通过 npm registry 把版本范围或 dist-tag 解析成确切版本；
3. 并行执行四维审计；
4. 返回 `allow`、`ask` 或 `deny`。`ask` 会进入 Harness 原生审批流程，命令尚未执行。

插件同时注册只读工具 `dep_check`，供 agent 在选型时比较包，或显式审计工作区 `package.json`。

要求：

- Node.js `^22.19.0 || >=24.0.0`
- DeepSeek Harness `>=0.1.0-rc.7 <0.2.0`

### 安装

把 bundle 安装到 DSH profile（下面使用 `web`）：

```sh
dsh plugin --profile web add dsh-install-guard
dsh --profile web --dump-config
dsh --profile web
```

包内含 `dsh.bundle` 声明，安装后会自动把 bundle 加入 profile。不要再手工 `insert` 同一个插件，否则可能产生重复的 loader id。

卸载：

```sh
dsh plugin --profile web remove dsh-install-guard
```

也可以从本地源码构建 tarball 后安装：

```sh
npm ci
npm pack
dsh plugin --profile web add ./dsh-install-guard-0.1.0.tgz
```

### 配置

bundle 插入的稳定 row id 是 `install-guard`。在 profile 的 `cordis.patch.yml`（默认位于 `$DSH_HOME/profiles/web/cordis.patch.yml`，未设置 `DSH_HOME` 时通常是 `~/.dsh/profiles/web/cordis.patch.yml`）中覆盖它：

```yaml
- id: install-guard
  config:
    denySeverity: high
    askSeverity: unknown
    blockedLicenses:
      - GPL
      - AGPL
    allowPackages:
      - '@your-company/*'
    maxBundleSizeKb: 20
    minWeeklyDownloads: 100
    minPackageAgeDays: 30
    typosquatMaxDistance: 1
    failClosed: false
```

DSH 的后置 patch 会替换该 row 的整个 `config`，不是深度合并；建议像上面一样列出完整配置。

| 配置 | 默认值 | 说明 |
| --- | --- | --- |
| `denySeverity` | `high` | 达到此漏洞等级时拒绝安装。可选 `critical`、`high`、`medium`、`low`、`unknown`。 |
| `askSeverity` | `unknown` | 达到此漏洞等级时要求人工确认。 |
| `blockedLicenses` | `["GPL", "AGPL"]` | 许可证黑名单；支持 SPDX 名称或系列前缀。 |
| `allowPackages` | `[]` | 完全跳过审计的包名；支持精确名称和 `@scope/*`。 |
| `maxBundleSizeKb` | `20` | 非 tree-shakeable 包允许的最大 gzip 体积（十进制 KB）。 |
| `minWeeklyDownloads` | `100` | 健康度启发式使用的最低周下载量。 |
| `minPackageAgeDays` | `30` | “新且低下载量”检查的最短包龄。 |
| `typosquatMaxDistance` | `1` | 与内置流行包名比较时允许的最大 Damerau–Levenshtein 距离。 |
| `failClosed` | `false` | 网络检查失败或只能使用过期缓存时是否要求人工确认。 |

`denySeverity` 应不低于 `askSeverity` 的风险范围；否则高风险项仍会以 `deny` 优先。白名单会跳过所有四项检查，应谨慎使用。

### 四维审计

#### 1. 漏洞

- 数据源：[`registry.npmjs.org`](https://registry.npmjs.org/) 与 [`api.osv.dev`](https://api.osv.dev/)。
- 先解析 `latest`、其他 dist-tag、精确版本或 semver 范围，再用确切版本查询 OSV npm ecosystem。
- 读取 OSV 的 CVSS v3 向量、数据库 severity、GHSA/CVE 与摘要；默认 HIGH/CRITICAL 为 `deny`，其余或未知等级为 `ask`。

#### 2. 许可证

- 数据源：npm registry 完整 packument 中目标版本的 `license`。
- 支持常见 SPDX `AND`、`OR`、`WITH` 表达式。`MIT OR GPL-3.0-only` 在默认策略下可接受；只有所有 `OR` 分支都命中黑名单才标记为 blocked。
- 黑名单命中或未声明许可证时返回 `ask`，不直接 `deny`。

#### 3. 体积

- 数据源：[`bundlephobia.com/api/size`](https://bundlephobia.com/api/size)。
- 使用 gzip 体积，并同时读取 `hasJSModule` 与 `hasSideEffects`。
- 超限且不能确认可安全 tree-shake 时返回 `ask`；可 tree-shake 的包只报告“实际体积取决于用法”，不会仅因整包体积被拦截。

#### 4. 包健康度

- 数据源：npm registry 的创建时间、弃用状态、维护者数量，以及 [`api.npmjs.org/downloads`](https://api.npmjs.org/downloads) 的最近一周下载量。
- 检查已弃用、无维护者、新且低下载量，以及低下载量包名与内置流行包过度相似（疑似 typosquatting）。
- 健康度启发式命中时返回 `ask`。

### `dep_check`

按包名比较候选依赖：

```json
{
  "packages": ["moment@^2", "dayjs@latest"]
}
```

显式审计工作区依赖：

```json
{
  "includePackageJson": true,
  "packageJsonPath": "package.json"
}
```

也可以同时提供 `packages` 和 `includePackageJson`。工具会：

- 审计 `dependencies`、`devDependencies`、`optionalDependencies` 与 `peerDependencies`；
- 合并相同 registry 包并保留来源；
- 跳过 `file:`、git、URL 等非 registry spec，并在结果中给出原因；
- 限制 manifest 路径在 agent 工作区内，拒绝 `..` 或 symlink 逃逸；
- 每次最多审计 1,000 个唯一 registry 包，每批并行处理 8 个；
- 为 `axios`、`chalk`、`lodash`、`moment`、`request`、`uuid` 返回经过人工整理的轻量替代品和迁移注意事项。

工具输出使用稳定的 `schemaVersion: 1` JSON，并汇总 `allow`、`ask`、`deny`、degraded 与 skipped 数量。它不会隐式扫描 `package.json`；必须显式设置 `includePackageJson: true`。

### 行为矩阵

| 输入或结果 | 默认行为 |
| --- | --- |
| 非 `bash` 工具、非 npm 安装命令 | 直接交给下游 |
| 无参数 `npm install`、`npm ci` | 直接交给下游（按现有 lockfile 安装） |
| `npm install/i/add` 的 registry 包 | 解析后审计 |
| HIGH / CRITICAL 漏洞 | `deny` |
| MEDIUM / LOW / UNKNOWN 漏洞 | `ask` |
| 许可证黑名单命中或缺失 | `ask` |
| gzip 超限、不能确认可 tree-shake | `ask` |
| gzip 超限、可 tree-shake | 报告但不拦截 |
| 健康度启发式命中 | `ask` |
| 所有检查干净 | 交给下游 |
| 网络失败，`failClosed: false` | fail-open，记录降级信息后交给下游 |
| 网络失败，`failClosed: true` | `ask` |
| 命中 `allowPackages` | 跳过所有检查并交给下游 |

一条命令安装多个包时会去重并行审计，最终采用最严格结果：`deny` > `ask` > `allow`。

支持 `npm install`、`npm i`、`npm add`，以及 `env`、`sudo`、`command`、环境变量前缀、npm 可执行文件绝对路径、`&&` / `;` / `||` 复合命令、引号与反斜杠转义。registry alias（例如 `alias@npm:real-package@2`）会审计真实包；本地路径、tarball URL 和 git spec 会被忽略。

### 隐私、缓存与数据源

插件不需要 API key，也不会读取或上传源码。

每次审计可能向以下公共服务发送最少信息：

| 服务 | 发送内容 | 用途 |
| --- | --- | --- |
| npm registry | 包名 | 解析版本、许可证和健康度元数据 |
| OSV.dev | 包名、确切版本、`npm` ecosystem | 查询公开漏洞 |
| Bundlephobia | 包名、确切版本 | 查询 bundle 体积与 tree-shaking 元数据 |
| npm downloads API | 包名 | 查询最近一周下载量 |

缓存只存在当前插件进程的内存中，不写磁盘：漏洞结果 TTL 为 24 小时，registry、体积和下载量元数据 TTL 为 7 天。TTL 到期且网络不可用时，插件会明确标记使用了过期值；默认 fail-open，`failClosed: true` 时要求人工确认。

### 限制

- 只拦截 Harness `bash` 工具中的 npm 安装请求；终端外部执行、其他工具名、pnpm 和 Yarn 目前不在拦截范围。
- 无参数 `npm install` 与 `npm ci` 不扫描 lockfile；如需审计声明依赖，请让 agent 调用 `dep_check`。
- 本地目录、git、tarball 和任意 URL 依赖不审计。
- 健康度与 typosquatting 是启发式信号，不是恶意软件证明；`ask` 需要人判断。
- 不验证 npm provenance、签名、maintainer 身份、安装脚本或包内容，也不替代锁文件审计、SBOM、EDR 或隔离执行。
- 第三方 API 可能限流、不可用或缺少某些包的数据；默认 fail-open 是可用性选择，不是安全保证。
- OSV CVSS v3 可以计算标准 base score；不支持的向量（例如 CVSS v4）会回退到数据源提供的等级或 unknown。
- 缓存是进程内的，Harness 重启后清空。

### 可复现演示

仓库提供确定性的演示脚本，它调用真实的插件 `apply()` 和 `tools/pre-execute` handler，但用固定 fixture 代替公共网络，不会真的安装包：

```sh
npm run build
node demo/interception.mjs
```

输出展示 `npm install lodash@4.17.20` 在执行前因 HIGH 漏洞被 `deny`。

生成终端 GIF 需要 [VHS](https://github.com/charmbracelet/vhs)：

```sh
./demo/record.sh
```

脚本会生成 `demo/interception.gif`。仓库不会用手工拼接或伪造的图片代替真实录制；没有 VHS 时，脚本会退出并打印安装与重试说明。

### 开发与测试

```sh
npm ci
npm run typecheck
npm test
npm run build
npm pack --dry-run
```

- `npm run typecheck`：严格 TypeScript 检查，不输出文件。
- `npm test`：运行 Vitest 测试。
- `npm run build`：清理并生成 `lib/`、声明文件和 source map。
- `npm run check`：依次执行 typecheck、test、build。
- `npm pack` / `npm publish` 会先运行 `prepack`，因此发布前自动执行完整检查。

## English

### Overview

`dsh-install-guard` is a DeepSeek Harness (DSH) bundle that listens to `tools/pre-execute`:

1. It selects npm install commands issued through the `bash` tool.
2. It resolves a range or dist-tag to an exact version through the npm registry.
3. It runs four audit dimensions concurrently.
4. It returns `allow`, `ask`, or `deny`. An `ask` decision enters Harness's native approval flow before the command executes.

The plugin also registers a read-only `dep_check` tool so an agent can compare candidate packages or explicitly audit a workspace `package.json`.

Requirements:

- Node.js `^22.19.0 || >=24.0.0`
- DeepSeek Harness `>=0.1.0-rc.7 <0.2.0`

### Installation

Install the bundle into a DSH profile (`web` in this example):

```sh
dsh plugin --profile web add dsh-install-guard
dsh --profile web --dump-config
dsh --profile web
```

The package declares `dsh.bundle`, so installation automatically adds the bundle to the profile. Do not manually insert the same plugin as well; doing so can create a duplicate loader id.

Remove it with:

```sh
dsh plugin --profile web remove dsh-install-guard
```

To build and install a local tarball:

```sh
npm ci
npm pack
dsh plugin --profile web add ./dsh-install-guard-0.1.0.tgz
```

### Configuration

The bundle inserts the stable row id `install-guard`. Override it in the profile's `cordis.patch.yml` (normally `$DSH_HOME/profiles/web/cordis.patch.yml`, or `~/.dsh/profiles/web/cordis.patch.yml` when `DSH_HOME` is unset):

```yaml
- id: install-guard
  config:
    denySeverity: high
    askSeverity: unknown
    blockedLicenses:
      - GPL
      - AGPL
    allowPackages:
      - '@your-company/*'
    maxBundleSizeKb: 20
    minWeeklyDownloads: 100
    minPackageAgeDays: 30
    typosquatMaxDistance: 1
    failClosed: false
```

A later DSH patch replaces the row's entire `config` value rather than deep-merging it, so listing every setting as above is recommended.

| Setting | Default | Meaning |
| --- | --- | --- |
| `denySeverity` | `high` | Deny at or above this vulnerability severity. Values: `critical`, `high`, `medium`, `low`, `unknown`. |
| `askSeverity` | `unknown` | Ask for human approval at or above this vulnerability severity. |
| `blockedLicenses` | `["GPL", "AGPL"]` | License denylist; SPDX names and family prefixes are supported. |
| `allowPackages` | `[]` | Package names that bypass the complete audit; supports exact names and `@scope/*`. |
| `maxBundleSizeKb` | `20` | Maximum gzip size in decimal KB for packages that are not tree-shakeable. |
| `minWeeklyDownloads` | `100` | Minimum weekly downloads used by health heuristics. |
| `minPackageAgeDays` | `30` | Minimum age used by the young-and-unpopular heuristic. |
| `typosquatMaxDistance` | `1` | Maximum Damerau–Levenshtein distance from the built-in popular-package list. |
| `failClosed` | `false` | Ask when a network check fails or only expired cache data is available. |

`deny` always wins over `ask` when thresholds overlap. An allowlisted package skips all four dimensions; use the allowlist sparingly.

### Four audit dimensions

#### 1. Vulnerabilities

- Sources: [`registry.npmjs.org`](https://registry.npmjs.org/) and [`api.osv.dev`](https://api.osv.dev/).
- Resolves `latest`, other dist-tags, exact versions, and semver ranges before querying the OSV npm ecosystem with the exact version.
- Reads CVSS v3 vectors, database severity, GHSA/CVE aliases, and summaries. HIGH/CRITICAL findings deny by default; lower or unknown findings ask.

#### 2. License

- Source: the target version's `license` value in the full npm registry packument.
- Understands common SPDX `AND`, `OR`, and `WITH` expressions. `MIT OR GPL-3.0-only` is allowed by the default policy; a license is blocked only when every `OR` branch contains a blocked term.
- A blocked or missing license asks for approval rather than denying outright.

#### 3. Bundle size

- Source: [`bundlephobia.com/api/size`](https://bundlephobia.com/api/size).
- Uses gzip size together with `hasJSModule` and `hasSideEffects`.
- An oversized package asks only when safe tree-shaking cannot be established. A tree-shakeable package is reported as usage-dependent but is not blocked for whole-package size alone.

#### 4. Package health

- Sources: npm registry creation/deprecation/maintainer metadata and the last-week endpoint at [`api.npmjs.org/downloads`](https://api.npmjs.org/downloads).
- Flags deprecated versions, zero maintainers, young and unpopular packages, and low-download names that are too close to a built-in popular package (possible typosquatting).
- Health signals ask for human approval.

### `dep_check`

Compare package candidates:

```json
{
  "packages": ["moment@^2", "dayjs@latest"]
}
```

Explicitly audit workspace dependencies:

```json
{
  "includePackageJson": true,
  "packageJsonPath": "package.json"
}
```

`packages` and `includePackageJson` may be combined. The tool:

- audits `dependencies`, `devDependencies`, `optionalDependencies`, and `peerDependencies`;
- deduplicates registry packages while preserving their sources;
- skips `file:`, git, URL, and other non-registry specs with an explicit reason;
- confines the manifest path to the agent workspace and rejects `..` and symlink escapes;
- accepts at most 1,000 unique registry packages per call and audits them in batches of 8;
- returns curated lighter alternatives and migration caveats for `axios`, `chalk`, `lodash`, `moment`, `request`, and `uuid`.

Output is stable `schemaVersion: 1` JSON with allow/ask/deny, degraded, and skipped counts. The tool never scans `package.json` implicitly; `includePackageJson: true` is required.

### Behavior matrix

| Input or result | Default behavior |
| --- | --- |
| Non-`bash` tool or non-install command | Continue downstream |
| Argument-free `npm install` or `npm ci` | Continue downstream (existing lockfile install) |
| Registry package in `npm install/i/add` | Resolve and audit |
| HIGH / CRITICAL vulnerability | `deny` |
| MEDIUM / LOW / UNKNOWN vulnerability | `ask` |
| Blocked or missing license | `ask` |
| Oversized gzip, not known to tree-shake safely | `ask` |
| Oversized gzip, tree-shakeable | Report without blocking |
| Health heuristic finding | `ask` |
| All checks clean | Continue downstream |
| Network failure with `failClosed: false` | Fail open, log degradation, continue |
| Network failure with `failClosed: true` | `ask` |
| Package matches `allowPackages` | Skip every check and continue |

For a multi-package command, requests are deduplicated and audited concurrently. The strongest aggregate result wins: `deny` > `ask` > `allow`.

The parser supports `npm install`, `npm i`, and `npm add`; `env`, `sudo`, and `command` wrappers; environment assignments; absolute npm executable paths; `&&`, `;`, and `||` compound commands; quoting; and backslash escapes. Registry aliases such as `alias@npm:real-package@2` audit the real package. Local paths, tarball URLs, and git specs are ignored.

### Privacy, cache, and data sources

No API key is required. The plugin does not read or upload source code.

Each audit may send the minimum package metadata to these public services:

| Service | Data sent | Purpose |
| --- | --- | --- |
| npm registry | Package name | Resolve versions, licenses, and health metadata |
| OSV.dev | Package name, exact version, `npm` ecosystem | Query public vulnerabilities |
| Bundlephobia | Package name and exact version | Query bundle size and tree-shaking metadata |
| npm downloads API | Package name | Query last-week downloads |

The cache is process memory only and never writes to disk. Vulnerability results have a 24-hour TTL; registry, size, and download metadata have a 7-day TTL. If data expires while offline, stale reuse is explicitly reported. The default is fail-open; `failClosed: true` asks for approval instead.

### Limitations

- Only npm install requests issued by the Harness `bash` tool are intercepted. External terminals, other tool names, pnpm, and Yarn are currently outside the guard.
- Argument-free `npm install` and `npm ci` do not scan a lockfile. Ask the agent to call `dep_check` to audit declared dependencies.
- Local directories, git dependencies, tarballs, and arbitrary URLs are not audited.
- Health and typosquatting findings are heuristics, not proof of malware; an `ask` decision needs human judgment.
- The plugin does not verify npm provenance, signatures, maintainer identities, install scripts, or package contents. It does not replace lockfile auditing, an SBOM, EDR, or sandboxing.
- Public APIs can be rate-limited, unavailable, or lack package data. Fail-open is an availability choice, not a security guarantee.
- Standard CVSS v3 base scores can be computed. Unsupported vectors such as CVSS v4 fall back to source severity or unknown.
- The in-memory cache is cleared when Harness restarts.

### Reproducible demo

The repository includes a deterministic demo that invokes the real plugin `apply()` and `tools/pre-execute` handler while replacing public network calls with fixed fixtures. It does not install a package:

```sh
npm run build
node demo/interception.mjs
```

It shows `npm install lodash@4.17.20` being denied before execution because of a HIGH vulnerability.

To generate a real terminal recording, install [VHS](https://github.com/charmbracelet/vhs) and run:

```sh
./demo/record.sh
```

The command writes `demo/interception.gif`. The repository intentionally does not substitute a hand-built or fabricated image when VHS is unavailable; the script prints installation and retry instructions instead.

### Development and verification

```sh
npm ci
npm run typecheck
npm test
npm run build
npm pack --dry-run
```

- `npm run typecheck` runs strict TypeScript checking without emitting files.
- `npm test` runs the Vitest suite.
- `npm run build` recreates `lib/`, declarations, and source maps.
- `npm run check` runs typecheck, tests, and build in sequence.
- `npm pack` and `npm publish` run `prepack`, so the complete check runs automatically before release.

## License

[MIT](./LICENSE)
# dsh-install-guard

DeepSeek Harness 的 npm 安装前漏洞门禁。插件监听 `tools/pre-execute`，在 `bash`
真正执行前解析 npm 安装命令、将版本范围或 dist-tag 解析为 registry 中的确切版本，
再查询 [OSV.dev](https://osv.dev/)。

当前第一阶段只覆盖漏洞审计：

- `CRITICAL` / `HIGH`：拒绝安装（`deny`）
- `MEDIUM` / `LOW` / 无等级漏洞：请求用户确认（`ask`）
- 无已知漏洞：直接交给后续处理器（`next()`）
- registry 或 OSV 审计失败：请求用户确认，不把失败误报为安全

许可证、体积、健康度、缓存、离线 fail-open、主动 `dep_check` 工具和发布流程不在
当前阶段范围内。

## 环境

- Node.js `^22.19.0` 或 `>=24.0.0`
- DeepSeek Harness `0.1.0-rc.7` 及兼容的 `0.1.x` 版本

## 开发

```sh
npm install
npm run typecheck
npm test
npm run build
```

本地 bundle 构建后可加入 DSH profile：

```sh
npx @deepseek-ai/dsh@0.1.0-rc.7 plugin --profile web add .
npx @deepseek-ai/dsh@0.1.0-rc.7 web
```

也可以用临时 patch 验证当前 checkout；patch 中的模块路径由 profile 目录解析，
因此需按 DSH 官方加载规则使用可解析的包名或绝对路径。

## 已支持的命令形态

- `npm install lodash`
- `npm i -D lodash@^4.17.0 @scope/name@next`
- `npm add foo bar@1`
- `cd packages/app && npm i foo`
- 由 `&&`、`||`、`;` 或换行连接的复合命令

无参数 `npm install`、`npm ci`、非安装命令、local/file/git/URL 依赖会直接放行。
解析器不会展开 shell 变量、alias、函数或命令替换。
