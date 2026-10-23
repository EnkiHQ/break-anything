<div align="center">

[English](../../README.md) · **简体中文**

# Break Anything · 攻破一切

### 一个 MCP,打穿代码、依赖、应用与基础设施里的漏洞。

**在别人动手之前先攻破它。把你的 Agent 指向你拥有的系统,找到弱点、证明它、修好它。**

[![npm version](https://img.shields.io/badge/npm-break--anything-cb3837?style=flat-square)](https://www.npmjs.com/package/break-anything)
[![MCP 工具目录](https://img.shields.io/badge/MCP-工具目录-5c4ee5?style=flat-square)](../mcp-tools.md)
[![仅限授权目标](https://img.shields.io/badge/范围-仅限授权目标-d13438?style=flat-square)](../../DISCLAIMER.md)
[![MIT license](https://img.shields.io/badge/license-MIT-f4c430?style=flat-square)](../../LICENSE)

**[快速开始](#快速开始) · [工作原理](#工作原理) · [能测什么](#能测什么) · [演示](#演示) · [FAQ](#faq) · [配套:Patch Anything](#配套patch-anything)**

<code>npx break-anything setup</code>

</div>

> [!IMPORTANT]
> Break Anything 只用于检测**你拥有、或已获得明确授权**的软件。
> 它是一个防御性、白盒的安全工具:每一条发现都附带证据和修复路径,每一个 PoC 都只打你自己的靶子。
> 它不是攻击框架,**严禁指向任何第三方系统**。

> [!WARNING]
> 只从本 README 和 `break-anything` npm 包中列出的官方来源获取 Break Anything。
> 相似的仓库名或抄来的 README 不代表那是官方版本。

---

看到一个漏洞上了新闻,心里打鼓——*我的*项目中招了没?让你的 Agent 用 Break Anything 查一遍。
它会检查你的代码、依赖、运行中的应用和基础设施,你不用去学十个扫描器;它告诉你**哪里**有漏洞、
用一条可复现的发现**证明**给你看,再把修复方案交给你的 Agent,或交给
[Patch Anything](#配套patch-anything)。

Break Anything 通过一个统一接口,把你的编码 Agent 接到成熟的安全工具链上(Semgrep、CodeQL、
OSV、Trivy、Grype、Nuclei、ZAP、gitleaks 等等)。同样的能力也能在终端里直接用。分析全程本地运行,
每条结果都带着证据、可利用性信号,以及它自身的局限。

大多数扫描器止步于"这是一张 CVE 列表,去升版本吧"。Break Anything 往前多走两步:它会推理一个漏洞
**在你的实际调用路径里到底能不能打通**,对**你自己的**靶子生成 PoC,并且——**当上游根本没有修复版本时**
——给出一个补丁、一层兼容 shim 或一个缓解方案,不让一个被遗弃的依赖变成你的事故。

## 快速开始

### 配置你的 Agent

装好 Node.js 和 npm 后运行:

```bash
npx break-anything setup
```

选择你的 Agent、检视将要做的改动、确认。Setup 会注册 Break Anything 的 MCP server 并安装配套的
工作流指令,并对现有配置做备份。完成后重启 Agent。

Setup 支持 Claude Code、Codex、Cursor、Gemini CLI、Windsurf,以及任何能运行本地 MCP server 的客户端。

### 对 Agent 说

```text
用 Break Anything 检查我的项目有没有漏洞。优先报在我代码里真正能被调用到的,
在我本地构建上证明给我看,然后给我一份修复方案。
```

把请求换成你的目标——一个仓库、一个 lockfile、一个本地运行的应用、一个容器镜像,或一个 Terraform 目录。

### 用终端

```bash
# 把项目依赖对 OSV / GHSA / KEV 扫一遍,带可达性 + EPSS
npx -y break-anything deps ./ --reachability --json

# 对注入、越权、反序列化、密钥做静态分析
npx -y break-anything sast ./src

# 扫容器镜像
npx -y break-anything image my-service:latest
```

常用的话,全局安装 `brk` 命令:

```bash
npm install --global break-anything
brk --help
```

> CLI 命令是 `brk`(不是 `break`,后者是 shell 关键字)。

### 更新

```bash
brk update
```

## 工作原理

你的 Agent 通过 MCP 调用 Break Anything 去检查一个你掌控的目标。Break Anything 把每条发现连同证据、
可利用性信号和建议的修复方式一起返回。Agent 据此排优先级、复现、修复。CLI 命令走同一套工作流。

![Break Anything 流程图](../assets/break-flow.svg)

调查模型:

| 阶段 | 做什么 |
| --- | --- |
| **Find 找** | 在依赖、源码、运行中的应用、基础设施里枚举弱点。 |
| **Prove 证** | 确认这个发现在你的用法里真的可达,并对*你的*靶子生成 PoC。 |
| **Fix 修** | 产出补丁、锁版本、shim 或缓解方案——自己修,或交给 Patch Anything。 |

Break Anything 会展示它是怎么得出每个结论的。它把"已确认可利用""可达但未证明""存在但不可达"
分开标注,而不是甩给你一堆噪音。

## 能测什么

| 目标 | Break Anything 返回什么 | 依赖 |
| --- | --- | --- |
| 依赖清单 | `package-lock`、`requirements.txt`、`go.mod`、`composer.lock`、`pom.xml`、`Cargo.toml` 里的已知 CVE;EPSS 利用概率;CISA KEV 状态;修复版本;调用路径可达性 | OSV / GHSA(内置);可达性用本地源码 |
| 源代码 | 注入、越权、不安全反序列化、路径穿越、SSRF、硬编码密钥——带数据流证据 | Semgrep / CodeQL 规则 |
| 仓库及 git 历史里的密钥 | 泄露的 API key、token、私钥,以及泄露的位置 | gitleaks / trufflehog 式扫描 |
| 运行中的 Web 应用(你的主机) | 对授权的 localhost 或预发目标做 OWASP Top 10 动态检测 | Chrome 系浏览器;OWASP ZAP |
| HTTP API(你的主机) | 越权、IDOR、认证绕过、批量赋值——带可复现请求 | 授权的 base URL + 凭据 |
| 容器镜像 | OS 层和应用层 CVE、配置错误、镜像层里的密钥 | Trivy / Grype |
| Dockerfile / IaC | Dockerfile、Terraform、Kubernetes、CloudFormation 里的配置错误 | Trivy / checkov 规则 |
| 前端打包产物 | 打进浏览器的脆弱 JS 库和密钥 | Node.js + npm |
| 编译产物 | 捆绑进去的已知脆弱依赖、内存安全隐患 | 静态检查 |
| 智能合约(可选) | Solidity 的重入、整数溢出、权限缺口 | Slither |

所有动态能力**默认关闭**,需要同时满足操作者策略和单次运行的显式授权标志。静态检查只读文件、不运行它们。

## 演示

十个完整 demo——**全部打在你自己拥有的、开源的、或故意做成脆弱的靶场上**。完整脚本见 [`demos/`](../../demos/)。

1. **OWASP Juice Shop** — 指向授权靶场,找到一个 IDOR,用一条请求证明,讲清怎么修。
2. **你忘了的那个依赖** — lockfile 里一个老 `lodash`/`minimist`:找到它,确认脆弱函数真的被调用,给出修复版本。
3. **php2shell 之后的 PHP 供应链** — 一个 PHP 项目锁了脆弱的 `composer` 依赖:Break Anything 把你整条依赖链画出来,让下一个 php2shell 不会打你个措手不及。
4. **Log4Shell 靶场** — 一个带脆弱 `log4j` 的 Java 服务:确认它从你的日志路径真的可达,而不只是"存在"。
5. **泄露的密钥** — 一个三个月前把 AWS key 提交进去的测试仓库:在历史里找到它,算出影响面。
6. **脆弱基础镜像** — 一个基于过期基础镜像的 `Dockerfile`:列出 OS + 应用 CVE 和最小升级方案。
7. **公开的桶** — 一个把 S3 桶设成全网可读的 Terraform 文件:在 `apply` 之前拦住。
8. **你自己的 Express API** — `/orders/:id` 上的一个 IDOR:用两个账号在 localhost 上证明。
9. **重入** — 靶场里的一个 Solidity 合约:追出状态更新之前的那个外部调用。
10. **Find → Fix 交接** — 把上面任意一条发现交给 [Patch Anything](#配套patch-anything),看它起草修复 PR。

如果你攻破了什么有意思的东西(而且你有权攻破它),开个 issue 或 PR,附上目标、你的问题和你的发现。

## 配套:Patch Anything

Break Anything 和 [Patch Anything](https://github.com/EnkiHQ/patch-anything) 是一对:

> **Break Anything** 找出来、证明它 → **Patch Anything** 修掉它。

当 Break Anything 报出一条发现,你的 Agent 可以直接把它递给 Patch Anything——后者生成补丁、依赖升级、
兼容 shim,或者在上游已死时给出维护中的 fork 或本地缓解。一个是进攻味的发现,一个是防御性的修复。
单用任一个都行,也可以把整条闭环跑通。

## FAQ

<details>
<summary><strong>这是攻击工具吗?会被下架吗?</strong></summary>

不是。Break Anything 是面向你拥有或已授权软件的防御性白盒工具。每个 PoC 都打你自己的靶子;
它不附带任何针对第三方系统的武器化 exploit。见 [DISCLAIMER.md](../../DISCLAIMER.md)。
GitHub 政策明确支持双用途安全研究。

</details>

<details>
<summary><strong>和 npm audit / Trivy / Snyk 有什么不同?</strong></summary>

那些工具报"存在"。Break Anything 多了**可达性**(脆弱代码在你项目里是否真被调用)、**证明**
(对你自己构建的 PoC),以及上游无修复时的**自救修复**。它还把依赖、源码、运行时、基础设施的发现
统一到一个 Agent 接口下。

</details>

<details>
<summary><strong>哪些 Agent 能用?</strong></summary>

任何支持本地 MCP server 的 Agent。Setup 会自动配置常见的那几个;其他的用手动 MCP 注册。

</details>

<details>
<summary><strong>会上传我的代码吗?</strong></summary>

分析在本地运行。你的 Agent 收到工具结果,它的模型提供商有自己的数据政策——那个你单独确认。

</details>

<details>
<summary><strong>能测一个我不拥有的网站吗?</strong></summary>

不能。动态能力需要显式授权标志,只用于你自己或合同授权的目标。未授权测试他人系统是违法的,也不受支持。

</details>

## 免责声明

Break Anything 用于合法的安全研究、教育,以及对你拥有或已授权软件的检测。责任使用指引见
[DISCLAIMER.md](../../DISCLAIMER.md)。你有责任在遵守所有适用法律、以及它所编排的任何第三方工具条款的
前提下使用本软件。

## 许可

[MIT](../../LICENSE)
