# aos-linux

AOS 版本 A：在 Linux 之上建立的独立世界，开机直接进入 AOS，运行在 QEMU 中。

- 平台规格：[`01-version-A-linux-world.md`](01-version-A-linux-world.md)
- 核心规格与核心库：[AngXiao01/aos-core](https://github.com/AngXiao01/aos-core)（必读，语义以它为准）
- 另一个版本：[AngXiao01/aos-microkernel](https://github.com/AngXiao01/aos-microkernel)

## 给实现 agent

1. 把 `aos-core` 克隆到本仓库同级目录（`../aos-core`），先读 `../aos-core/00-core-spec.md`，再读本仓库的平台规格。
2. 核心库代码放在 `aos-core`，本仓库只放平台层：镜像构建、服务拆分、隔离、出口强制、存储布局、kiosk 界面。
3. 决定写进 `DECISIONS.md`，矛盾写进 `QUESTIONS.md`。
