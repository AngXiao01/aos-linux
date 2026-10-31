# aos-linux

AOS（agent-native OS）的 Linux 版：在 Linux 内核之上建立独立的 AOS 世界，开机直接进入，运行在 QEMU 中。

本仓库自成一体，不依赖任何其他仓库。唯一的规格文件是 [`SPEC.md`](SPEC.md)，第一部分规定系统语义，第二部分规定平台实现。

## 给实现 agent

1. 先读 `SPEC.md` 的 §0，再通读全文。
2. 按 §18 的仓库布局组织代码。核心库、人的界面、iPhone 确认器都在本仓库内实现。
3. 决定写进 `DECISIONS.md`，矛盾写进 `QUESTIONS.md`。

## 开发

核心库在 `core/`，是一个 Cargo workspace，工具链版本由 `core/rust-toolchain.toml` 固定。

```bash
cd core && cargo test
```

§7.8 的性能目标用基准程序测量：

```bash
cd core && cargo run --release -p aos-branch --example bench
```
