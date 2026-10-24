<div align="center">

[English](../../README.md) · **简体中文**

# Break Anything · 攻破一切

### 一个 MCP server,把你的编码 Agent 变成一支安全团队。

**指向任何你拥有的东西——代码、依赖树、容器、运行中的应用、你的云——它找出哪里有洞、在你自己的靶子上证明它、再把修复方案交给你。**

[![npm version](https://img.shields.io/badge/npm-break--anything-cb3837?style=flat-square)](https://www.npmjs.com/package/break-anything)
[![MCP 工具目录](https://img.shields.io/badge/MCP-工具目录-5c4ee5?style=flat-square)](../mcp-tools.md)
[![仅限授权目标](https://img.shields.io/badge/范围-仅限授权目标-d13438?style=flat-square)](../../DISCLAIMER.md)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

**[快速开始](#快速开始) · [能扫什么](#你可以指给它什么) · [覆盖能力](#覆盖能力与工具链) · [什么时候用它](#什么时候用它) · [工作原理](#工作原理) · [FAQ](#faq)**

<code>npx break-anything setup</code>

</div>

> [!IMPORTANT]
> Break Anything 只用于检测**你拥有、或已获得明确授权**的软件。
> 它是防御性、白盒工具:每条发现都带证据和修复方案,每个 PoC 都只打你自己的靶子。
> 它不是攻击框架,**严禁指向任何第三方系统**。

> [!WARNING]
> 只从本 README 和 `break-anything` npm 包中列出的官方来源获取。相似仓库名或抄来的 README 不代表官方。

<div align="center">

<img src="../assets/hero.gif" alt="Break Anything" width="900" />

</div>

---

凌晨两点,一个高危 CVE 爆了。你的服务中招没有?你那四十个依赖里,到底哪个**真的调用**到了脆弱代码、哪些只是噪音?你去年回滚的那次提交里,是不是还躺着一个仍然有效的 API key?你马上要 `apply` 的那份 Terraform,会不会把一个桶开给了整个互联网?

过去回答这些问题,意味着装十个扫描器、学十套命令行、淹没在一万条告警里。**Break Anything 把这一切收进一个接口,交给你的 Agent。** 用大白话问它,它去跑对应的业界标准工具、把结果关联起来,告诉你**哪里**暴露、**是否真的可达**、以及**怎么修**——附带一个在你自己构建上跑出来的 PoC,而不是 CVE 库里一段吓人的描述。

大多数扫描器止步于"这有个 CVE,去升版本"。Break Anything 多走两步:

- **看可达性,不只看"存在"。** 它把*已确认可利用*、*可达*、*存在但是死代码*分开,让你只修那三条要命的,而不是去分诊四百条不相干的。
- **上游没了也能自救。** 当根本没有修复版本——维护者消失了、仓库归档了——它给你一个补丁、一个锁版本、一层兼容 shim,或一个维护中的 fork,不让一个被遗弃的依赖变成你的事故。

全程本地运行。每条结果都带证据、可利用性信号和它自身的局限。绝不指向任何你不拥有的东西。

## 为什么用 Break Anything

| | |
| --- | --- |
| 🧠 **为 Agent 而生** | 一句话说出担忧,Agent 自己选工具、跑工具、读结果——不用背任何扫描器命令行。 |
| 🎯 **要信号不要噪音** | 按可达性 + EPSS + CISA KEV 排序,高危、可达、正被利用的那几条浮到最上面。 |
| 🔬 **给证据不给空话** | 在*你自己*构建上跑出的 PoC,把"理论上有洞"变成"就是这条请求能打穿"。 |
| 🛠️ **真工具,一个接口** | 编排安全团队本就信任的扫描器——OSV、Trivy、Semgrep、CodeQL、ZAP、Nuclei、gitleaks、Checkov、Slither。 |
| 🔒 **本地 + 防御** | 分析留在本机;动态扫描默认关闭,拒绝任何不在白名单里的目标。 |
| 🔁 **找→修闭环** | 把任意发现交给 [Patch Anything](#配套patch-anything) 出可合并的修复,或在同一会话里直接修。 |

## 快速开始

```bash
npx break-anything setup
```

选 Agent、看改动、确认。支持 Claude Code、Codex、Cursor、Gemini CLI、Windsurf,以及任何能跑本地 MCP 的客户端。

对 Agent 说:

```text
用 Break Anything 扫这个项目。找出我代码里真正可达的漏洞,在我本地构建上证明最严重的那个,给我一份按优先级排好的修复方案。
```

或用终端:

```bash
npx -y break-anything deps ./              # 依赖 CVE,按可达性 + EPSS 排序
npx -y break-anything secrets ./ --history # 工作区 + 完整 git 历史里的泄露密钥
npx -y break-anything image my-svc:latest  # 容器镜像的 OS + 应用层 CVE
```

> **今日已发:** `deps`、`secrets`、`image` 及对应 MCP 工具。[军火库](#军火库)其余部分在路线图上,逐步接入——每个引擎只在能返回同样带证据的发现后才接。

## 工作原理

Agent 通过 MCP 调用 Break Anything 检查一个你掌控的目标;它路由到正确的引擎、关联发现、确认可达性,每条结果都带证据和修复返回。CLI 走同一套工作流。

![Break Anything 流程图](../assets/break-flow.svg)

| 阶段 | 做什么 |
| --- | --- |
| **Find 找** | 在依赖、源码、密钥、镜像、IaC、运行应用里枚举弱点。 |
| **Prove 证** | 确认在你用法里可达,并对*你的*靶子生成 PoC。 |
| **Fix 修** | 产出补丁、锁版本、shim 或缓解——直接修,或交给 Patch Anything。 |

每条发现都标注 `confirmed` · `reachable` · `present` · `not-reachable`。"未发现"绝不等于"安全"。

## 你可以指给它什么

你不用自己选模式。把手头有的东西丢给 Break Anything,它会**自动识别是什么形态**,再路由到对应引擎。

| 你给它 | 形态 | 对应类别 |
| --- | --- | --- |
| 一个仓库 / 源码目录 | 源码 / 技术栈 | 依赖漏洞、代码漏洞、密钥 |
| 一个 lockfile(`package-lock.json`、`composer.lock`、`go.mod`…) | 依赖清单 | 依赖漏洞 |
| 一个容器镜像 | 构建产物 | 容器 |
| 一个 APK / IPA 或编译二进制 | 构建产物 | 移动、模糊测试 |
| 一份 Terraform / Kubernetes / Dockerfile | 配置 | 基础设施配置 |
| 一个运行中的网址或 API(你自己的) | 活体系统 | 运行应用、API |
| 云账号凭据(你自己的) | 活体账号 | 云配置体检 |
| git 历史 | 仓库元数据 | 密钥 |

不像只能吃编译产物的检查器,Break Anything **横跨源码、构建产物、配置、活体系统**——你指给它,剩下的它来判断。

## 覆盖能力与工具链

Break Anything 按**扫描类别**组织(安全圈通用的分法),每一类都编排从业者本就在用的工具——没有一个是凑数的,都是真实 CI 流水线和真实渗透里在跑的引擎。(括号里是行业缩写,破折号后面是它干什么、再后面是用到的工具。)

图例:✅ 0.1.0 已发 · 🧭 路线图

- **✅ 依赖漏洞(SCA / 软件成分分析)** — 在你整棵依赖树里找有已知漏洞(CVE)的包,并按"你是否真的调用到"排序。工具:OSV / osv-scanner、Trivy、Grype、pip-audit、govulncheck、composer audit、OWASP Dependency-Check;覆盖 npm/PyPI/Composer/Go/Maven/Cargo/RubyGems/NuGet;叠加 EPSS(利用概率)+ CISA KEV(已在野利用)。
- **✅ 泄露密钥(Secrets)** — 揪出误提交的密钥 / 令牌 / 私钥,连你以为删掉的历史提交里也找得出。工具:Gitleaks、TruffleHog、detect-secrets。
- **✅ 容器镜像** — 扫你真正要发布的镜像,逐层检查。工具:Trivy、Grype、Dockle、Hadolint;找 OS + 应用层 CVE、Dockerfile 坏味道、层里埋的密钥。
- **🧭 代码漏洞(SAST / 静态应用安全测试)** — 直接读源码,在上线前找出漏洞代码并给出数据流证据。工具:Semgrep、CodeQL,分语言 Bandit(Py)、gosec(Go)、Brakeman(Rails)、Find-Sec-Bugs(Java)、Psalm(PHP)、njsscan(JS);找注入、XSS、越权、反序列化、路径穿越、SSRF、弱加密。
- **🧭 基础设施配置(IaC / 基础设施即代码)** — 在 `apply` 上线之前查出云配置错误。工具:Checkov、tfsec、Terrascan、KICS、kube-bench;覆盖 Terraform/CloudFormation/K8s/Helm/Dockerfile;找公开存储桶、开放安全组、缺加密、过宽的 IAM 权限。
- **🧭 云配置体检(CSPM / 云安全态势管理)** — 按安全基线体检你自己的云账号。工具:Prowler、ScoutSuite;AWS/GCP/Azure,对标 CIS/PCI/SOC2。
- **🧭 运行应用(DAST / 动态应用安全测试)** — 像外部攻击者那样打你自己运行中的应用(需授权)。工具:OWASP ZAP、Nuclei、Nikto、Wapiti、sqlmap;找 OWASP Top 10、注入、XSS、SSRF、认证缺陷,每条都带能复现的请求。
- **🧭 API 安全** — 查 API 的逻辑漏洞。工具:Schemathesis(按 OpenAPI 规范做模糊测试)、ZAP;找越权(IDOR/BOLA)、认证绕过、批量赋值、数据过度暴露。
- **🧭 攻击面 / 资产测绘** — 看清你把哪些东西暴露到了公网(仅限你自己的域名和主机)。工具:Nmap、ProjectDiscovery(subfinder/httpx/naabu);找被遗忘的子域、暴露的服务、开放端口。
- **🧭 智能合约(Web3)** — 工具:Slither、Mythril、Echidna;找重入、整数溢出、权限缺口、预言机操纵。
- **🧭 移动 App** — 工具:MobSF、APKiD;吃 APK/IPA;找不安全存储、硬编码密钥、弱加密、导出组件。
- **🧭 模糊测试(Fuzzing)** — 工具:AFL++、libFuzzer、Jazzer、Atheris;找崩溃和内存安全 bug,每个都带最小复现样本。

逐工具的完整目录和 MCP 契约见 [docs/mcp-tools.md](../mcp-tools.md)。所有动态(会发流量)的类别**默认关闭**,并拒绝任何不在授权白名单里的目标。

## 什么时候用它

| 这一刻 | 类别 | Break Anything 做什么 |
| --- | --- | --- |
| "某 CVE 在刷屏——我们中招没?" | SCA | 画出依赖树,只标可达的,给修复版本 |
| "有人提交密钥了吗?" | Secrets | 扫工作区 + 完整历史,脱敏,定位引入的 commit |
| "我们镜像在带着已知洞发布吗?" | 容器 | OS + 应用 CVE、Dockerfile 坏味道、层里的密钥 |
| "这份 Terraform 看着危险。" | IaC | 在 `apply` 前标出公开桶 / 开放端口 / 过宽 IAM |
| "用户 A 能读到用户 B 的数据吗?" | API/DAST | 用两个账号 + 一条请求证明(或排除)这个 IDOR |
| "我们的依赖被弃了、还没补丁。" | SCA + 自救 | 给出补丁、锁版本、shim 或维护中的 fork |
| "快上线了,把所有东西过一遍。" | 全部 | 一句 prompt,关联发现,一份排好序的修复方案 |

## 演示

十个完整 demo——**全部打你自己拥有的、开源的、或故意做脆弱的靶场**。脚本见 [`demos/`](../../demos/)。

1. OWASP Juice Shop 的 IDOR;2. 你忘了的那个旧依赖;3. php2shell 之后的 PHP 供应链;4. Log4Shell 可达性;5. git 历史里的泄露密钥;6. 脆弱基础镜像;7. 公开的 S3 桶;8. 你自己 Express API 的 IDOR;9. 合约重入;10. Find→Fix 交接给 Patch Anything。

## 配套:Patch Anything

Break Anything 和 [Patch Anything](https://github.com/EnkiHQ/patch-anything) 是一对:

> **Break Anything** 找出来、证明它 → **Patch Anything** 修掉它。

把任意发现交给 Patch Anything,它起草补丁、依赖升级、兼容 shim,或在上游已死时给维护中的 fork。发现与修复,一个闭环。

## FAQ

<details><summary><strong>这是攻击工具吗?会被下架吗?</strong></summary>

不是。防御性白盒工具,只针对你拥有或已授权的软件。每个 PoC 都打你自己的靶子,不含任何针对第三方的武器化 exploit。见 [DISCLAIMER.md](../../DISCLAIMER.md)。GitHub 政策明确支持双用途安全研究。

</details>

<details><summary><strong>和 npm audit / Trivy / Snyk 有什么不同?</strong></summary>

那些报"存在"。Break Anything 多了**可达性**、**证明**(对你自己构建的 PoC)、以及上游无修复时的**自救修复**,还把依赖/代码/密钥/镜像/IaC/运行时统一到一个 Agent 接口下。

</details>

<details><summary><strong>它取代这些工具吗?</strong></summary>

不,它编排它们。Break Anything 是大脑和接口,OSV/Trivy/Semgrep/ZAP 是引擎。你拿到它们的深度,又不用逐个去学。

</details>

<details><summary><strong>会上传我的代码吗?</strong></summary>

分析在本地。Agent 收到结果,其模型提供商有自己的数据政策,单独确认。

</details>

<details><summary><strong>能测我不拥有的站点吗?</strong></summary>

不能。动态能力需要显式授权标志,只用于你自己或合同授权的目标。未授权测试违法且不受支持。

</details>

## 许可

[MIT](../../LICENSE)。Break 自身代码为 MIT;编排的第三方引擎各自保留其许可证,见 [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md)。
