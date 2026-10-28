<div align="center">

[English](../../README.md) · **简体中文**

# Break Anything · 攻破一切

### 你以为你的服务很安全。你从没站在攻击者的角度看过它。

Break Anything 把你的编码 Agent(或你的终端)指向你自己的代码、应用和基础设施,**像攻击者一样**审视它们:挖出真正可被利用的那些、在你自己构建上证明给你看、再修掉。赶在别人先找到之前。

[![npm version](https://img.shields.io/npm/v/break-anything?color=cb3837&logo=npm)](https://www.npmjs.com/package/break-anything)
[![npm downloads](https://img.shields.io/npm/dm/break-anything?color=cb3837)](https://www.npmjs.com/package/break-anything)
[![CI](https://img.shields.io/github/actions/workflow/status/EnkiHQ/break-anything/ci.yml?branch=main&label=CI&logo=github)](https://github.com/EnkiHQ/break-anything/actions)
[![node](https://img.shields.io/node/v/break-anything)](https://nodejs.org)
[![MCP 工具](https://img.shields.io/badge/MCP-9_工具-5c4ee5)](../mcp-tools.md)
[![仅限授权目标](https://img.shields.io/badge/范围-仅限授权目标-d13438)](../../DISCLAIMER.md)
[![license](https://img.shields.io/npm/l/break-anything?color=f4c430)](../../LICENSE)

**[快速开始](#快速开始) · [示例输出](#示例输出) · [凭什么不一样](#凭什么不一样) · [CI/CD](#一行接入-cicd) · [军火库](#军火库) · [FAQ](#faq)**

```bash
npx break-anything ci .          # 一条命令:deps + secrets + IaC + SAST,一个退出码
```

</div>

> [!IMPORTANT]
> Break Anything 只检测**你拥有、或已获得明确授权**的软件。每个 PoC 都只打你自己的靶子。
> 它是防御工具,不是攻击框架,严禁指向任何第三方系统。见 [DISCLAIMER.md](../../DISCLAIMER.md)。

<div align="center">

<img src="../assets/hero.gif" alt="Break Anything" width="900" />

</div>

---

"应该没事吧。" 上线了、能跑、没人投诉,于是你默认它是安全的。但"还没出事"从来不是一次安全检测。唯一诚实的检测,是像攻击者那样审视你自己的服务:哪个依赖是一扇敞开的门、哪把 key 还躺在 git 历史里、哪个接口在把别人的数据交出去。

而且,安全没有终点。2026 年 10 月,一个未授权的高危 RCE 在 PHP 自己身上被挖了出来、藏了好几年——连撑起大半个互联网的语言都还在冒高危洞,你的应用凭什么没有。你每加一个依赖,攻击面就更大一圈,而且你补不完所有洞。所以只补攻击者*今天*真能够到的那几条。

而且游戏规则刚变了:同样会写代码的 AI Agent,如今正被用来大规模地挖漏洞——攻击者手里也有。抢在他们前面,用同样的杠杆先找到你自己的洞。

**Break Anything 把这双"攻击者的眼睛"交给你的 Agent**——一句话,只针对你拥有的软件:挖出真正可被利用的、在*你自己*构建上证明、连修复一起给你。全程本地,绝不指向任何你不拥有的东西。

## 快速开始

**作为 Agent 工具(MCP)。** 一行命令把 Break Anything 注册进本机每一个 AI 编码 Agent:

```bash
npx break-anything setup
```

它自动探测 Claude Desktop、Claude Code、Cursor、Codex、Gemini CLI、Windsurf——每个文件先备份、保留你原有的其它 server、可安全重复运行。重启 Agent,然后直接说:

```text
用 Break Anything 扫这个项目。只给我代码里真正可达的漏洞,证明最严重的那条,给我修复方案。
```

**用终端。** 免安装、零配置:

```bash
npx -y break-anything ci .                 # 全仓库门禁:deps + secrets + IaC + SAST,一个退出码
npx -y break-anything deps .               # 依赖 CVE,按可达性 + KEV + EPSS 排序
npx -y break-anything secrets . --history  # 工作区 + 完整 git 历史里的泄露密钥
npx -y break-anything iac ./deploy         # Dockerfile/K8s/Terraform 错误配置——免装引擎
npx -y break-anything sast ./src           # 静态分析(需 Semgrep):注入、越权、SSRF…
npx -y break-anything image my-svc:latest  # 容器镜像的 OS + 应用层 CVE(需 Trivy)
npx -y break-anything api http://localhost:4000 --config accounts.json  # 运行中 API 的越权/鉴权检测(需授权)
npx -y break-anything fix .                # 把发现变成按优先级排序的升级计划
npx -y break-anything sbom . --out bom.json  # 生成 CycloneDX SBOM(--diff 旧SBOM 卡漂移)
```

需要 Node.js ≥ 18.17。`deps`/`secrets`/`iac`/`fix`/`sbom` 全部内置;`sast` 和 `image` 封装 Semgrep/Trivy,没装会优雅降级。

## 示例输出

`brk ci` —— 整个仓库,一个门禁,一个退出码:

```text
Break Anything · CI 安全门禁
./my-service

  ● 依赖          9 条发现
  ● 密钥          1 条发现
  ● iac          3 条发现
  • 代码(SAST)    跳过 (Semgrep not installed)

合计 13 条  ·  CRITICAL 2  HIGH 7  MEDIUM 4

✗ 门禁失败 (阈值 HIGH)
  - 4 reachable HIGH+ dependency vulns
  - 1 known-exploited (KEV) dependency vuln
  - 1 leaked secret
  - 1 HIGH+ IaC issue
```

`brk deps` —— 按"攻击者真够得到的"排序,在野利用的那条单独标红:

```text
Break Anything · 依赖扫描
目标 ./my-service  ·  已扫 2 个包  ·  npm:2

HIGH     systeminformation@5.3.0 (npm) [KEV在野利用]
  CVE-2021-21315  ·  被调用  ·  EPSS 90.7%  ·  修复 → 5.3.1
  Command Injection Vulnerability
CRITICAL lodash@4.17.4 (npm)
  CVE-2019-10744  ·  被调用  ·  EPSS 5.0%  ·  修复 → 4.17.12
  Prototype Pollution in lodash

小结 12 条  ·  12 可达 (10 被调用)  ·  1 KEV在野利用  ·  CRITICAL 2  HIGH 8  MEDIUM 2
KEV = CISA 已知被在野利用:攻击者此刻正在打它。优先修这些。
```

`brk fix` —— 一次升级关掉最多 CVE 的最小版本,按可达性排序:

```text
Break Anything · 修复计划
./my-service  ·  2 个包待升级  ·  可消除 12 个漏洞

1. [被调用 · CRITICAL] [KEV在野利用] systeminformation 5.3.0 → 5.31.7  消除 9 个 CVE
   npm install systeminformation@5.31.7
2. [被调用 · CRITICAL] lodash 4.17.4 → 4.18.0  消除 3 个 CVE
   npm install lodash@4.18.0
```

## 凭什么不一样

扫描器都能甩你一张清单。清单本身就是问题。Break Anything 做的是清单做不到的三件事:

- **看可达性——它像攻击者一样思考。** 攻击者不会挨个去看你那 400 条理论 CVE,他们只冲那几条真能够到的。Break Anything 也一样排序:`called`(被调用)→ `imported`(已引用)→ `direct`(直接依赖)→ `transitive`(传递依赖)。它不只判断脆弱包"在不在",而是把你从该包导入的符号抽出来,检查你的代码是否真的**调用**了它们。你从不调用的那个脆弱 `lodash` 是噪音;你真调用的那个才是发现。你分诊 3 条,不是 400 条。
- **给证据,不给空话。** 不是甩一段 CVSS 描述,而是在*你自己*构建上跑出一个 PoC——那条能打穿它的具体输入或请求——把"理论上有洞"变成"这就是复现"。API 探测会把"读到了另一个账号数据"的那条请求原样还给你。
- **上游没了也给你修。** 维护者消失、没有修复版本?它给你一个补丁、一个锁版本、一层兼容 shim,或一个维护中的 fork,不让一个被遗弃的依赖变成你的事故。交给 [Patch Anything](#配套patch-anything) 还能直接出可合并的 PR。

它不取代 OSV、Trivy、Semgrep、ZAP——而是把它们**编排**在一个接口(CLI 或 MCP)下,再做它们做不了的推理。

### 横向对比

| | `npm audit` | Trivy / Grype | Snyk | **Break Anything** |
| --- | :---: | :---: | :---: | :---: |
| 列出已知 CVE | ✅ | ✅ | ✅ | ✅ |
| 可达性(是否真被调用) | ✗ | ✗ | 部分 | ✅ `被调用` vs `已引用` |
| 在野利用(CISA KEV)+ EPSS 排序 | ✗ | 部分 | ✅ | ✅ |
| 对*你自己*构建的 PoC 证明 | ✗ | ✗ | ✗ | ✅(API/DAST) |
| 上游无补丁时的修复方案 | ✗ | ✗ | 部分 | ✅ |
| 依赖+密钥+IaC+SAST+运行时 统一 | ✗ | 部分 | ✅ | ✅ 一个门禁 |
| 本地运行、无需账号 | ✅ | ✅ | ✗ | ✅ |
| Agent 原生(MCP) | ✗ | ✗ | ✗ | ✅ 9 个工具 |

## 30 秒看懂

三个你会用到它的时刻,每个都是一句话丢给 Agent:

| 这一刻 | 你问 | 它给你 |
| --- | --- | --- |
| **"某 CVE 在刷屏——我们中招没?"** | *"扫我依赖,只标可达的。"* | 3 条可达 CVE + 修复版本,而不是 400 行的墙 |
| **"有人提交密钥了吗?"** | *"扫仓库和 git 历史里的密钥。"* | 泄露的 key、引入它的 commit、"去轮换别只删" |
| **"用户 A 能读到用户 B 的数据吗?"** | *"查 /orders/:id 的越权。"* | 那个 IDOR,用两个账号在 localhost 上证明给你看 |

## 一行接入 CI/CD

`brk ci` 在门禁触发时以非零码退出,直接塞进任何流水线。加上 SARIF,发现就会内联显示在 GitHub Security 页对应的文件/行:

```yaml
# .github/workflows/security.yml
name: security
on: [push, pull_request]
jobs:
  break-anything:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: "22" }

      - name: 安全门禁(可达高危 / KEV / 密钥 命中即让构建失败)
        run: npx -y break-anything ci . --fail-on=high

      - name: 导出 SARIF
        if: always()
        run: npx -y break-anything ci . --sarif > results.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

其它 CI 一样能用——本质就是个退出码。GitLab、CircleCI、Jenkins:跑 `npx -y break-anything ci .` 看状态即可。

**用策略文件调门禁。** 在仓库根放一个 `.break-anything.json`,设阈值、跳过类别、把已接受的历史发现做成基线——让门禁只卡**新增**的,而不是开局就被一堆旧账卡死:

```json
{
  "failOn": "high",
  "skip": ["sast"],
  "ignore": [
    "CVE-2019-10744",
    { "id": "docker-no-user", "reason": "基础镜像已加固" }
  ]
}
```

## 输出格式

每个产出发现的命令都讲你工具链已经认识的格式:

| 格式 | 开关 | 用在哪 |
| --- | --- | --- |
| 人类可读 | *(默认)* | 终端阅读;带颜色、严重度、可达性 |
| JSON | `--json` | 脚本、Agent、自定义面板 |
| SARIF 2.1.0 | `--sarif` | GitHub / GitLab 代码扫描、IDE 安全面板 |
| CycloneDX SBOM | `brk sbom` | 归档、审计,`--diff` 卡依赖漂移 |

## 你可以指给它什么

你不用自己选模式。把手头的东西丢给它,它自动识别形态、路由到对应引擎。

| 你给它 | 形态 | 对应类别 |
| --- | --- | --- |
| 一个仓库 / 源码目录 | 源码 / 技术栈 | 依赖、代码、密钥、IaC |
| 一个 lockfile(`package-lock.json`、`yarn.lock`、`pnpm-lock.yaml`、`go.mod`、`pom.xml`…) | 依赖清单 | 依赖 |
| 一个容器镜像 | 构建产物 | 容器 |
| 一份 Terraform / Kubernetes / Dockerfile | 配置 | 基础设施配置 |
| 一个运行中的网址或 API(你自己的) | 活体系统 | 运行应用、API |
| git 历史 | 仓库元数据 | 密钥 |

## 军火库

按**扫描类别**组织(安全团队的通用语言),每类都编排真实流水线里在跑的工具。✅ 已发 · 🧭 路线图。

### ✅ 今日已发

- **依赖(SCA)** — 整棵依赖树的已知 CVE,按**可达性** + [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)(在野已利用)+ [EPSS](https://www.first.org/epss/)(被利用概率)排序,带修复版本。由 [OSV](https://osv.dev) 驱动。**8 个生态:** npm(package-lock / yarn / pnpm)、PyPI、Composer(PHP)、Go、Rust(crates.io)、Ruby(RubyGems)、Maven(Java)、NuGet(.NET)。
- **密钥(Secrets)** — 工作区 + 完整 git 历史里的泄露 key/令牌/私钥,输出里脱敏。内置;识别 AWS、GCP、GitHub、GitLab、Slack、Stripe、OpenAI、JWT、私钥和通用赋值密钥。
- **静态代码(SAST)** — 注入、越权、不安全反序列化、SSRF、硬编码密钥——每条带文件/行号、CWE/OWASP 标签和命中片段。引擎:[Semgrep](https://semgrep.dev)。
- **基础设施即代码(IaC)** — Dockerfile、Kubernetes、Terraform 的错误配置(以 root 运行的容器、特权 Pod、对全网开放的 CIDR、公开桶、烤进镜像的密钥),每条带文件/行号、CWE 和修复建议。**内置,免装任何引擎。**
- **容器镜像** — OS + 应用层 CVE、Dockerfile 坏味道、层里的密钥。引擎:[Trivy](https://github.com/aquasecurity/trivy)。
- **API 安全(DAST)** — 对一个*运行中*的 API 探测越权(IDOR/BOLA)、缺失鉴权、缺失安全响应头,每条都**带可复现的请求作为证据**。内置;默认关闭,仅限授权目标。
- **修复规划(Fix)** — 每个包算出"能一次消掉最多 CVE 的最小安全版本",按可达性再按严重度排序,给出确切的 `npm`/`pip`/`composer` 命令。没有修复版本的单列并给缓解建议。
- **标准制品输出** — CycloneDX SBOM 生成 + 比对,以及所有扫描器的 SARIF 2.1.0 输出。
- **一键 CI 门禁** — `ci` 一条命令跑完 deps + secrets + IaC + SAST,一份报告、一份合并 SARIF、一个退出码。

### 🧭 路线图

- **更多 SAST 引擎** — [CodeQL](https://codeql.github.com)、Bandit(Py)、gosec(Go)、Brakeman(Rails)、Find-Sec-Bugs(Java)、security-code-scan(.NET)、retire.js(前端)。
- **更深的 IaC 与云** — 可选接入 [Checkov](https://www.checkov.io)、tfsec、[KICS](https://kics.io)、[Kubescape](https://github.com/kubescape/kubescape);CloudFormation、ARM/Bicep、Ansible;云配置 CSPM 用 [Prowler](https://github.com/prowler-cloud/prowler) / ScoutSuite。
- **更多 DAST 与攻击面** — 在越权探测之上增加 OWASP Top 10、目录/参数发现、XSS、注入。[OWASP ZAP](https://www.zaproxy.org)、[Nuclei](https://github.com/projectdiscovery/nuclei)、[sqlmap](https://sqlmap.org);攻击面测绘用 [Nmap](https://nmap.org) + ProjectDiscovery。
- **调用链级可达性** — 从"符号被调用"升级到"公告里那个具体脆弱函数真在调用链上"。
- **AI/大模型 · 二进制 · 移动 · 模糊测试** — [Garak](https://github.com/NVIDIA/garak) · [Ghidra](https://ghidra-sre.org)/[angr](https://github.com/angr/angr) · [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) · [AFL++](https://github.com/AFLplusplus/AFLplusplus)。
- **进攻 / 漏洞利用** — *仅限授权渗透;默认关闭、需显式开启、须书面授权。* [Metasploit](https://www.metasploit.com)、[Hydra](https://github.com/vanhauser-thc/thc-hydra)、[BloodHound](https://github.com/SpecterOps/BloodHound)。

逐工具完整目录和 MCP 契约见 [docs/mcp-tools.md](../mcp-tools.md)。所有动态(发流量)类别**默认关闭**,拒绝任何不在白名单里的目标。

## 数据源

Break Anything 只信开放、权威的数据源,不靠封闭的私有库:

- **[OSV.dev](https://osv.dev)** — 覆盖所有主流开源生态的漏洞,每条公告都来自权威上游(GitHub Advisory、RustSec、Ubuntu 等)。
- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** — 美国 CISA 维护的"此刻正被在野利用"的权威目录。
- **[EPSS](https://www.first.org/epss/)**(FIRST.org)— 未来 30 天内被利用的概率。

分析在你本机进行。除了查公告所需的"包名+版本"坐标,不上传任何东西。

## 工作原理

Agent(或 CLI)调用 Break Anything 检查一个你掌控的目标;它路由到对应引擎、确认可达性,每条结果带证据和修复返回。

![Find Prove Fix 流程](../assets/break-flow.svg)

**Find 找**(依赖/代码/密钥/镜像/IaC/运行应用里的弱点)→ **Prove 证**(对你的靶子生成 PoC 证明可达)→ **Fix 修**(直接修,或交给 Patch Anything)。"未发现"绝不等于"安全"。

## 配套:Patch Anything

> **Break Anything** 找出来、证明它 → **[Patch Anything](https://github.com/EnkiHQ/patch-anything)** 修掉它。

把任意发现交给它,起草补丁、升级、shim 或 fork。发现与修复,一个闭环。

## FAQ

<details><summary><strong>和 npm audit / Trivy / Snyk 有什么不同?</strong></summary>

它们报"存在"——依赖树里任何地方存在的每个漏洞。Break Anything 多了**可达性**(是否真被调用)、**KEV + EPSS 排序**(是否在野利用/被利用概率)、**证明**(对你自己构建的 PoC)、以及上游无修复时的**自救修复**,还把依赖/代码/密钥/镜像/IaC/运行时统一到一个接口下。见[横向对比](#横向对比)。

</details>

<details><summary><strong>它取代这些工具吗?</strong></summary>

不,它编排它们。Break Anything 是大脑和接口,OSV/Trivy/Semgrep/ZAP 是引擎。你拿到它们的深度,又不用逐个去学。

</details>

<details><summary><strong>不用 AI Agent 也能用吗?</strong></summary>

能。`brk` CLI 跟 MCP 工具做的事一模一样——`npx -y break-anything ci .` 不需要 Agent、不需要账号、不需要配置。MCP server 只是把同样的能力暴露给支持它的 Agent。

</details>

<details><summary><strong>这是攻击工具吗?会被下架吗?</strong></summary>

不是。防御性、仅授权目标;每个 PoC 都打你自己的靶子,不含武器化 exploit。见 [DISCLAIMER.md](../../DISCLAIMER.md)。GitHub 政策明确支持双用途安全研究。

</details>

<details><summary><strong>会上传我的代码吗?</strong></summary>

分析在本地。依赖查询只把"包名+版本"发给 OSV。Agent 收到结果,其模型提供商有自己的数据政策,单独确认。

</details>

<details><summary><strong>哪些 Agent 能用?</strong></summary>

任何支持本地 MCP server 的 Agent。`npx break-anything setup` 自动配置常见的那几个(Claude Desktop、Claude Code、Cursor、Codex、Gemini CLI、Windsurf)。

</details>

## 许可

[MIT](../../LICENSE)。Break 自身代码为 MIT;编排的引擎各自保留其许可证,见 [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)。
