# aos-linux

AOS（agent-native OS）的 Linux 版：在 Linux 内核之上建立独立的 AOS 世界，开机直接进入，运行在 QEMU 中。人和 agent 读写同一份对象图；内部修改可撤销；发送、付款、上传、把数据发给外部（包括云端模型）只能经过出口闸门，放行签名来自用户 iPhone 的安全芯片。

本仓库自成一体，不依赖任何其他仓库。唯一的规格文件是 [`SPEC.md`](SPEC.md)：第一部分是系统语义，第二部分是 Linux + QEMU 上的平台实现。实现中的决定写在 [`DECISIONS.md`](DECISIONS.md)，规格矛盾的处理写在 [`QUESTIONS.md`](QUESTIONS.md)。当前没有未决问题。

许可是 MIT，全文见 [`LICENSE`](LICENSE)。版权持有人 Ang Xiao，2026。

`main` 上有的是核心库 `core/`，做到 §17 的 M3。镜像、服务拆分、人的界面和 iPhone 确认器还没有目录；那些属于 §A11 的平台里程碑。

## 现状

里程碑以验收测试通过为完成标准（§0、§16.4）。下表只记 `main`。

| 里程碑 | 规格 | `main` |
|---|---|---|
| M0 | 核心库骨架：类型、对象、CBOR、哈希 | 已落地。`aos-types` |
| M1 | 日志、事务、分支、变更单、撤销 | 已落地。`aos-log`、`aos-branch`（内存后端，持久化是 `LogStore` 接口） |
| M2 | 动作声明、WASM 运行时、宿主 ABI、能力令牌 | 已落地。[#1](https://github.com/AngXiao01/aos-linux/pull/1)。`aos-cap`、`aos-action` |
| M3 | 出口意图、策略引擎、出口闸门、开发确认器 | 已落地。[#2](https://github.com/AngXiao01/aos-linux/pull/2)。`aos-policy`、`aos-confirm`、`aos-egress` |
| M4 | Agent Host、MCP agent 视图、任务报告 | 未开始。下一步 |
| M5–M8 | §17 | 未开始 |
| A-0–A-7 | §A11 | 未开始 |

接上闸门后，意图在动作事务提交前评估常设规则。`allow` 在事务提交成功之后才发出；`confirm` 保持 pending；`deny` 不发送。没接闸门时，`intent_create` 仍只留下 `pending` 意图。

## 下一步

最新落地的是 M3。下一步按 §17 做 **M4**：Agent Host、MCP agent 视图、任务报告。验收是让 agent 完成一个纯内部任务并送审。范围以该节为准。

## 给实现 agent

1. 先读 `SPEC.md` 的 §0，再通读全文。
2. 按 §18 的仓库布局组织代码。核心库、人的界面、iPhone 确认器都在本仓库内实现。
3. 决定写进 `DECISIONS.md`，矛盾写进 `QUESTIONS.md`。
4. 做「下一步」里的那一档。没进 `main` 的里程碑，按「现状」写成未合并。

## 开发

核心库在 `core/`，是一个 Cargo workspace。工具链由 `core/rust-toolchain.toml` 固定，当前 channel 是 `1.97.0`，组件含 rustfmt 和 clippy。需要 rustup；在 `core/` 里跑 cargo 时会选用这个版本。workspace 里的 crate 设了 `publish = false`。

```bash
cd core && cargo test
```

§7.8 的性能目标用基准程序测量：

```bash
cd core && cargo run --release -p aos-branch --example bench
```

目前没有可启动的镜像，也没有 `run-aos.sh`。那是 §A3 和 A-1 的事。
