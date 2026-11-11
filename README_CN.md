# tfguard · 中文说明

[English README](README.md) · 零依赖 Terraform / OpenTofu 配置审计。

**一句话**：`password = var.db_password` 看着像「用了变量所以安全」，真正那个
密钥在**变量声明那一行**。tfguard 做的是凭据溯源与跨块关系，不是逐行正则。

## 目录

- [为什么存在](#为什么存在)
- [三步跑通](#三步跑通)
- [差异化](#差异化)
- [命令](#命令)
- [已知边界](#已知边界)

## 为什么存在

tfsec（约 7k★）、terrascan（约 5.2k★）是 Go；checkov（约 9.1k★）是 Python 但带
一车依赖。零依赖、能在跳板机 / 瘦容器里直接跑的 Python 赛道空着。

更根本的是判定方式：Terraform 的风险很少落在单条属性上。

- 安全组放通 22 端口，本身是一条 finding；公网实例正好落在这个组里，是另一条；
  合起来才是「可被直连」。
- 硬编码密钥会被抓到；`var.db_password` 不会——除非沿着引用找到变量默认值、
  `.tfvars`、环境变量，看它到底从哪来。
- `resource` 与 `data` 块之间的引用关系决定了谁能读到谁。

## 三步跑通

```bash
# 1) 安装（零运行时依赖，自带 HCL2 子集解析器）
pip install git+https://github.com/xuange-hu/tfguard

# 2) 看结构 / 跑自带演示（离线，实测 demo 输出 8 critical / 16 high /
#    23 medium / 5 low / 2 info，覆盖 11 个文件 23 个资源）
tfguard parse main.tf
tfguard demo

# 3) 扫目录并卡 CI
tfguard scan ./infra --fail-on high --format sarif --output tfguard.sarif
```

`tfguard demo` 已在干净目录实测：`rc=0`，输出 232 行报告。

## 差异化

| 能力 | 说明 |
|---|---|
| **自写 HCL2 解析器** | 保留行号，不依赖 python-hcl2 / PyYAML |
| **凭据溯源** | 沿 `var.*` 引用追到默认值、`.tfvars`、环境变量 |
| **跨块关系图** | `graph` 把 resource / data / variable 连起来看 |
| **40 规则** | 5 个级别，逐条可用 `explain` 看原理与修法 |
| **MCP 工具** | `uvx --from "tfguard[mcp]" tfguard-mcp` |

## 命令

| 命令 | 作用 |
|---|---|
| `tfguard scan PATH` | 扫目录或单个 `.tf` 文件 |
| `tfguard rules` | 列出全部规则 |
| `tfguard explain RULE` | 单条规则为什么存在、怎么修 |
| `tfguard demo` | 生成故意写坏的工作区并给出报告 |
| `tfguard parse FILE` | 打印解析后的结构（排查误报的第一步） |
| `tfguard graph` | 打印块之间的引用关系 |

## 已知边界

- 不执行 `terraform plan`，因此看不到 provider 计算出的最终值；
- HCL2 子集不支持任意复杂的动态表达式（`for_each` 的高阶组合等），遇到会显式标注；
- 模块来自远端 registry 时，只能审计本地可见的引用，不能拉取远端源码。

贡献见 [CONTRIBUTING.md](CONTRIBUTING.md)，安全问题见 [SECURITY.md](SECURITY.md)。MIT。
