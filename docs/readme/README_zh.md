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

而且,安全没有终点。2026 年 10 月,一个未授权的高危 RCE 在 PHP 自己身上被挖了出来、藏了好几年(php2shell)——连撑起大半个互联网的语言都还在冒高危洞,你的应用凭什么没有。你每加一个依赖,攻击面就更大一圈,而且你补不完所有洞。所以只补攻击者*今天*真能够到的那几条。

而且游戏规则刚变了:同样会写代码的 AI Agent,如今正被用来大规模地挖漏洞——攻击者手里也有。抢在他们前面,用同样的杠杆先找到你自己的洞。

**Break Anything 把这双"攻击者的眼睛"交给你的编码 Agent**——一句话,只针对你拥有的软件:挖出真正可被利用的、在*你自己*构建上证明、连修复一起给你。全程本地,绝不指向任何你不拥有的东西。

## 快速开始

```bash
npx break-anything setup
```

一行命令。它自动探测本机的 Claude Desktop、Claude Code、Cursor、Codex、Gemini CLI、Windsurf,把 Break Anything 注册进每一个——每个文件先备份、保留你原有的其它 server、可安全重复运行。重启 Agent,然后直接说:

```text
用 Break Anything 扫这个项目。只给我代码里真正可达的漏洞,证明最严重的那条,给我修复方案。
```

想用终端?一行命令,今天就能跑:

```bash
npx -y break-anything deps ./              # 依赖 CVE,按可达性 + EPSS 排序
npx -y break-anything secrets ./ --history # 工作区 + 完整 git 历史里的泄露密钥
npx -y break-anything image my-svc:latest  # 容器镜像的 OS + 应用层 CVE
npx -y break-anything sast ./src           # 静态代码分析(注入、越权、SSRF…)
npx -y break-anything iac ./deploy         # IaC 错误配置(Dockerfile/K8s/Terraform)——免安装
npx -y break-anything api http://localhost:4000 --config accounts.json  # 运行中 API 的越权/鉴权检测(需授权)
npx -y break-anything fix ./             # 把依赖发现变成按优先级排序的升级计划
```

## 凭什么不一样

扫描器都能甩你一张清单。清单本身就是问题。Break Anything 做的是清单做不到的三件事:

- **看可达性——它像攻击者一样思考。** 攻击者不会挨个去看你那 400 条理论 CVE,他们只冲那几条真能够到的。Break Anything 也一样排序:`called`(被调用)→ `imported`(已引用)→ `direct`(直接依赖)→ `transitive`(传递依赖)。它不只判断脆弱包"在不在",而是把你从该包导入的符号抽出来,检查你的代码是否真的**调用**了它们。你从不调用的那个脆弱 `lodash` 是噪音;你真调用的那个才是发现。你分诊 3 条,不是 400 条。
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

按**扫描类别**组织(安全团队的通用语言),每类都编排真实流水线里在跑的工具。✅ 0.7.0 已发 · 🧭 路线图。

### ✅ 今日已发

- **依赖(SCA)** — 整棵依赖树的已知 CVE,按可达性 + [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)(在野已利用)+ EPSS 排序,带修复版本。引擎:[OSV](https://osv.dev)、[Trivy](https://github.com/aquasecurity/trivy)、[Grype](https://github.com/anchore/grype)、pip-audit、govulncheck、composer audit。覆盖 npm/PyPI/Composer/Go/Maven/Cargo/RubyGems/NuGet。
- **密钥(Secrets)** — 工作区 + 完整 git 历史里的泄露 key/令牌/私钥,脱敏。引擎:[Gitleaks](https://github.com/gitleaks/gitleaks)、[TruffleHog](https://github.com/trufflesecurity/trufflehog)。
- **容器镜像** — OS + 应用层 CVE、Dockerfile 坏味道、层里的密钥。引擎:[Trivy](https://github.com/aquasecurity/trivy)、[Grype](https://github.com/anchore/grype)、[Hadolint](https://github.com/hadolint/hadolint)。
- **静态代码(SAST)** — 注入、越权、不安全反序列化、SSRF、硬编码密钥——每条带文件/行号、CWE/OWASP 标签和命中代码片段。引擎:[Semgrep](https://semgrep.dev)。
- **基础设施即代码(IaC)** — Dockerfile、Kubernetes、Terraform 的错误配置(以 root 运行的容器、特权 Pod、对全网开放的 CIDR、公开桶、烤进镜像的密钥),每条带文件/行号、CWE 和修复建议。内置实现,免装任何引擎。
- **API 安全(DAST)** — 对一个*运行中*的 API 探测越权(IDOR/BOLA)、缺失鉴权、缺失安全响应头,每条都带可复现的请求作为证据。内置实现;默认关闭,仅限授权目标。
- **修复规划(Fix)** — 把发现变成按优先级排序的升级计划:每个包算出"能一次消掉最多 CVE 的最小安全版本",按可达性再按严重度排序,给出确切的 `npm`/`pip`/`composer` 命令。没有修复版本的单列并给缓解建议。

### 🧭 路线图

- **更多 SAST 引擎** — [CodeQL](https://codeql.github.com)、SonarQube CE、Bandit(Py)、gosec(Go)、Brakeman(Rails)、Find-Sec-Bugs(Java)、security-code-scan(.NET)、retire.js(前端 JS)。
- **更深的 IaC 与云** — 在内置规则之上,可选接入 [Checkov](https://www.checkov.io)、tfsec、[KICS](https://kics.io)、[Kubescape](https://github.com/kubescape/kubescape) 等引擎,并扩展 CloudFormation、ARM/Bicep、Ansible 和完整 CIS 基线。
- **更多 DAST 与攻击面** — 在今天的越权探测之上,增加 OWASP Top 10、目录/参数发现、XSS、注入,打你授权的应用。[OWASP ZAP](https://www.zaproxy.org)、[Nuclei](https://github.com/projectdiscovery/nuclei)、[Nikto](https://github.com/sullo/nikto)、[ffuf](https://github.com/ffuf/ffuf)、[Katana](https://github.com/projectdiscovery/katana)、[Dalfox](https://github.com/hahwul/dalfox)、[sqlmap](https://sqlmap.org);攻击面测绘用 [Nmap](https://nmap.org) + [Amass](https://github.com/owasp-amass/amass) + ProjectDiscovery。
- **更多 API 检测** — 批量赋值、过度数据暴露、基于 OpenAPI 的模糊测试(OWASP API Top 10)。[Schemathesis](https://github.com/schemathesis/schemathesis)、ZAP。
- **进攻 / 漏洞利用** — *仅限授权渗透;默认关闭、需显式开启、须书面授权。* 在你拥有的目标上证明可利用性。[Metasploit](https://www.metasploit.com)、sqlmap、[Hydra](https://github.com/vanhauser-thc/thc-hydra)、[Hashcat](https://hashcat.net)、[BloodHound](https://github.com/SpecterOps/BloodHound) + Impacket(域渗透)、[OpenVAS](https://www.openvas.org)。
- **AI / 大模型安全** — 对你自己的模型和 Agent 做提示注入、越狱、数据泄露检测。[Garak](https://github.com/NVIDIA/garak)。
- **二进制与产物分析** — 编译二进制里的已知脆弱依赖和不安全模式。[Ghidra](https://ghidra-sre.org)、[radare2](https://github.com/radareorg/radare2)、[angr](https://github.com/angr/angr)(与 REA 互补)。
- **云配置 · 智能合约 · 移动 · 模糊测试** — [Prowler](https://github.com/prowler-cloud/prowler) · [Slither](https://github.com/crytic/slither)、Mythril、Echidna · [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) · [AFL++](https://github.com/AFLplusplus/AFLplusplus)、libFuzzer、Jazzer。

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
