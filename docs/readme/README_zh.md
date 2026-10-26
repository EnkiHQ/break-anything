<div align="center">

[English](../../README.md) · **简体中文**

# Break Anything · 攻破一切

### 你以为你的服务很安全。你从没站在攻击者的角度看过它。

Break Anything 把你的编码 Agent 指向你自己的代码、应用和基础设施,**像攻击者一样**审视它们——挖出真正可被利用的那些、在你自己构建上证明给你看、再修掉。赶在别人先找到之前。

*用攻击者的眼睛,看你自己的服务。*

[![npm version](https://img.shields.io/badge/npm-break--anything-cb3837?style=flat-square)](https://www.npmjs.com/package/break-anything)
[![MCP 工具目录](https://img.shields.io/badge/MCP-工具目录-5c4ee5?style=flat-square)](../mcp-tools.md)
[![仅限授权目标](https://img.shields.io/badge/范围-仅限授权目标-d13438?style=flat-square)](../../DISCLAIMER.md)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

**[快速开始](#快速开始) · [凭什么不一样](#凭什么不一样) · [30 秒看懂](#30-秒看懂) · [军火库](#军火库) · [FAQ](#faq)**

<code>npx break-anything setup</code>

</div>

> [!IMPORTANT]
> Break Anything 只检测**你拥有、或已获得明确授权**的软件。每个 PoC 都只打你自己的靶子。
> 它是防御工具,不是攻击框架,严禁指向任何第三方系统。

<div align="center">

<img src="../assets/hero.gif" alt="Break Anything" width="900" />

</div>

---

"应该没事吧。" 上线了、能跑、没人投诉,于是你默认它是安全的。但"还没出事"从来不是一次安全检测。唯一诚实的检测,是像攻击者那样审视你自己的服务:哪个依赖是一扇敞开的门、哪把 key 还躺在 git 历史里、哪个接口在把别人的数据交出去。

大多数开发者从没做过这个检测——工具一大堆太难上手,请一次真人渗透又贵得离谱。**Break Anything 把这双"攻击者的眼睛"交给你的编码 Agent**——一句话,只针对你拥有的软件。它挖出真正可被利用的问题、在*你自己*构建上证明给你看、再把修复递给你。全程本地,绝不指向任何你不拥有的东西。

## 快速开始

```bash
npx break-anything setup
```

选 Agent、确认改动、重启。支持 Claude Code、Codex、Cursor、Gemini CLI、Windsurf,以及任何能跑本地 MCP 的客户端。然后直接说:

```text
用 Break Anything 扫这个项目。只给我代码里真正可达的漏洞,证明最严重的那条,给我修复方案。
```

想用终端?一行命令,今天就能跑:

```bash
npx -y break-anything deps ./              # 依赖 CVE,按可达性 + EPSS 排序
npx -y break-anything secrets ./ --history # 工作区 + 完整 git 历史里的泄露密钥
npx -y break-anything image my-svc:latest  # 容器镜像的 OS + 应用层 CVE
```

## 凭什么不一样

扫描器都能甩你一张清单。清单本身就是问题。Break Anything 做的是清单做不到的三件事:

- **看可达性——它像攻击者一样思考。** 攻击者不会挨个去看你那 400 条理论 CVE,他们只冲那几条真能够到的。Break Anything 也一样:把 `confirmed`(已确认)→ `reachable`(可达)→ `present`(存在)→ `not-reachable`(不可达)分开。你从不调用的那个脆弱 `lodash` 是噪音;活代码路径上的那个才是发现。你分诊 3 条,不是 400 条。
- **给证据,不给空话。** 不是甩一段 CVSS 描述,而是在*你自己*构建上跑出一个 PoC——那条能打穿它的具体输入或请求——把"理论上有洞"变成"这就是复现"。
- **上游没了也给你修。** 维护者消失、没有修复版本?它给你一个补丁、一个锁版本、一层兼容 shim,或一个维护中的 fork,不让一个被遗弃的依赖变成你的事故。交给 [Patch Anything](#配套patch-anything) 还能直接出可合并的 PR。

它不取代 OSV、Trivy、Semgrep、ZAP——而是把它们**编排**在一个 Agent 接口下,再做它们做不了的推理。

## 30 秒看懂

三个你会用到它的时刻,每个都是一句话丢给 Agent:

| 这一刻 | 你问 | 它给你 |
| --- | --- | --- |
| **"某 CVE 在刷屏——我们中招没?"** | *"扫我依赖,只标可达的。"* | 3 条可达 CVE + 修复版本,而不是 400 行的墙 |
| **"有人提交密钥了吗?"** | *"扫仓库和 git 历史里的密钥。"* | 泄露的 key、引入它的 commit、"去轮换别只删" |
| **"用户 A 能读到用户 B 的数据吗?"** | *"查 /orders/:id 的越权。"* | 那个 IDOR,用两个账号在 localhost 上证明给你看 |

## 你可以指给它什么

你不用自己选模式。把手头的东西丢给它,它自动识别形态、路由到对应引擎。

| 你给它 | 形态 | 对应类别 |
| --- | --- | --- |
| 一个仓库 / 源码目录 | 源码 / 技术栈 | 依赖、代码、密钥 |
| 一个 lockfile(`package-lock.json`、`composer.lock`、`go.mod`…) | 依赖清单 | 依赖 |
| 一个容器镜像 | 构建产物 | 容器 |
| 一个 APK / IPA 或编译二进制 | 构建产物 | 移动、模糊测试 |
| 一份 Terraform / Kubernetes / Dockerfile | 配置 | 基础设施配置 |
| 一个运行中的网址或 API(你自己的) | 活体系统 | 运行应用、API |
| 云账号凭据(你自己的) | 活体账号 | 云配置 |
| git 历史 | 仓库元数据 | 密钥 |

## 军火库

按**扫描类别**组织(安全团队的通用语言),每类都编排真实流水线里在跑的工具。✅ 0.1.0 已发 · 🧭 路线图。

### ✅ 今日已发

- **依赖(SCA)** — 整棵依赖树的已知 CVE,按可达性 + EPSS 排序,带修复版本。引擎:[OSV](https://osv.dev)、[Trivy](https://github.com/aquasecurity/trivy)、[Grype](https://github.com/anchore/grype)、pip-audit、govulncheck、composer audit。覆盖 npm/PyPI/Composer/Go/Maven/Cargo/RubyGems/NuGet。
- **密钥(Secrets)** — 工作区 + 完整 git 历史里的泄露 key/令牌/私钥,脱敏。引擎:[Gitleaks](https://github.com/gitleaks/gitleaks)、[TruffleHog](https://github.com/trufflesecurity/trufflehog)。
- **容器镜像** — OS + 应用层 CVE、Dockerfile 坏味道、层里的密钥。引擎:[Trivy](https://github.com/aquasecurity/trivy)、[Grype](https://github.com/anchore/grype)、[Hadolint](https://github.com/hadolint/hadolint)。

### 🧭 路线图

- **静态代码(SAST)** — 注入、越权、反序列化、SSRF,带数据流。[Semgrep](https://semgrep.dev)、[CodeQL](https://codeql.github.com)、Bandit、gosec、Brakeman。
- **基础设施(IaC)** — `apply` 前揪出公开桶、开放端口、过宽 IAM。[Checkov](https://www.checkov.io)、tfsec、Terrascan、KICS。
- **运行应用(DAST)** — 对你授权的应用做 OWASP Top 10。[OWASP ZAP](https://www.zaproxy.org)、[Nuclei](https://github.com/projectdiscovery/nuclei)、sqlmap。
- **API** — 越权(IDOR/BOLA)、认证绕过、批量赋值。[Schemathesis](https://github.com/schemathesis/schemathesis)。
- **云配置 · 攻击面 · 智能合约 · 移动 · 模糊测试** — Prowler、Nmap + ProjectDiscovery、[Slither](https://github.com/crytic/slither)、[MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)、[AFL++](https://github.com/AFLplusplus/AFLplusplus)。

逐工具完整目录和 MCP 契约见 [docs/mcp-tools.md](../mcp-tools.md)。所有动态(发流量)类别**默认关闭**,拒绝任何不在白名单里的目标。

## 工作原理

Agent 通过 MCP 调用 Break Anything 检查一个你掌控的目标;它路由到对应引擎、确认可达性,每条结果带证据和修复返回。CLI 走同一套工作流。

![Find Prove Fix 流程](../assets/break-flow.svg)

**Find 找**(依赖/代码/密钥/镜像/IaC/运行应用里的弱点)→ **Prove 证**(对你的靶子生成 PoC 证明可达)→ **Fix 修**(直接修,或交给 Patch Anything)。"未发现"绝不等于"安全"。

## 配套:Patch Anything

> **Break Anything** 找出来、证明它 → **[Patch Anything](https://github.com/EnkiHQ/patch-anything)** 修掉它。

把任意发现交给它,起草补丁、升级、shim 或 fork。发现与修复,一个闭环。

## FAQ

<details><summary><strong>和 npm audit / Trivy / Snyk 有什么不同?</strong></summary>

它们报"存在"——依赖树里任何地方存在的每个漏洞。Break Anything 多了**可达性**(是否真被调用)、**证明**(对你自己构建的 PoC)、以及上游无修复时的**自救修复**,还把依赖/代码/密钥/镜像/IaC/运行时统一到一个 Agent 接口下。

</details>

<details><summary><strong>它取代这些工具吗?</strong></summary>

不,它编排它们。Break Anything 是大脑和接口,OSV/Trivy/Semgrep/ZAP 是引擎。你拿到它们的深度,又不用逐个去学。

</details>

<details><summary><strong>这是攻击工具吗?会被下架吗?</strong></summary>

不是。防御性、仅授权目标;每个 PoC 都打你自己的靶子,不含武器化 exploit。见 [DISCLAIMER.md](../../DISCLAIMER.md)。GitHub 政策明确支持双用途安全研究。

</details>

<details><summary><strong>会上传我的代码吗?</strong></summary>

分析在本地。Agent 收到结果,其模型提供商有自己的数据政策,单独确认。

</details>

<details><summary><strong>哪些 Agent 能用?</strong></summary>

任何支持本地 MCP server 的 Agent。Setup 自动配置常见的那几个。

</details>

## 许可

[MIT](../../LICENSE)。Break 自身代码为 MIT;编排的引擎各自保留其许可证,见 [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)。
