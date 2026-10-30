# AOS 需求文档 · 版本 A：Linux 上的独立世界

> 前置阅读：`00-core-spec.md`。本文件只规定平台相关部分，所有语义以核心规格为准。

---

## A1. 定位

- 复用 Linux 内核、驱动和成熟的用户态工具，在其上建立 AOS 的整个世界。
- 开机直接进入 AOS：用户看不到 Linux 桌面，也拿不到 shell，agent 同样拿不到。
- 目标是尽快跑通核心规格的全部语义，并且出口不变量（核心 §11.4）由内核机制**强制**保证，而不是靠进程自觉。
- 规模粗估：核心库加平台层合计数万行代码（猜测，不是测量值）。

---

## A2. 运行环境

用户没有专用的实体机，因此 v1 **只支持虚拟机**。

| 宿主 | 客户机架构 | QEMU 机型与加速 |
|---|---|---|
| Apple Silicon Mac | aarch64 | `-machine virt -accel hvf` |
| x86_64 Linux | x86_64 | `-machine q35 -accel kvm` |
| x86_64 Windows | x86_64 | `-machine q35 -accel whpx` |

- **主目标**：与宿主机同架构（实现 agent 应先确认宿主机是什么，再在 `DECISIONS.md` 里记录选择）。另一种架构 SHOULD 能构建，但可以用 TCG 慢速运行。
- 资源基线：4 vCPU、8 GB 内存、64 GB 磁盘。
- 设备：virtio-blk、virtio-net（user 模式 + 端口转发）、virtio-gpu、virtio-input、virtio-rng；宿主文件夹通过 virtiofs 或 9p 以**只读**方式共享。
- **开发模式**：所有服务 MAY 直接跑在 Linux 容器（Docker）里，以加快迭代。但平台安全测试（§A10）MUST 在完整虚拟机镜像上运行。

---

## A3. 镜像构建

- 基础发行版：Debian stable 最小安装（备选 Alpine），使用 `mkosi` 构建，输出 qcow2。
- 镜像只包含：内核、systemd、AOS 服务、计算沙箱用的 Python 运行时、kiosk 浏览器组件。**不安装**：shell 登录入口（debug 构建除外）、包管理器的运行时访问、SSH 服务。
- 构建 SHOULD 可复现，并固定所有依赖版本。
- 根文件系统只读，并使用 dm-verity 校验（release 构建）；可写数据只放在 `/aos` 分区。
- 产物：`aos-<arch>-<version>.qcow2`，以及一个启动脚本 `run-aos.sh`（含端口转发和共享文件夹参数）。

---

## A4. 启动流程

1. 内核 → systemd。
2. 按顺序启动 `aos-store` → `aos-core`（日志、分支、类型、能力、策略）→ `aos-egress` → `aos-confirm` → `aos-runtime` → `aos-jobs` → `aos-agent` → `aos-view`。
3. `aos-kiosk` 启动 `cage`（Wayland kiosk 合成器）+ `cog`（WPE WebKit），全屏打开 `http://127.0.0.1:<view_port>`。
4. 首次启动：界面显示配对二维码（核心 §12.2）。配对完成之前，所有出口通道都处于 `deny` 状态。

---

## A5. 进程与隔离

每个服务以独立的系统用户运行。

| 服务 | 用户 | 网络 | 文件访问 | 额外隔离 |
|---|---|---|---|---|
| aos-store | aos-store | 无 | `/aos/log` `/aos/cas` `/aos/index`（读写） | seccomp、Landlock |
| aos-core | aos-core | 仅本机 Unix socket | 无（经 aos-store） | seccomp、Landlock |
| aos-egress | aos-egress | **唯一允许出站的用户** | 无 | seccomp |
| aos-confirm | aos-confirm | 只允许入站监听配对端口 | 无 | seccomp |
| aos-runtime | aos-runtime | 无 | 无 | wasmtime 沙箱 + seccomp |
| aos-jobs | aos-jobs | 无 | 通过沙箱挂载 | 每个作业放进 bubblewrap/nsjail |
| aos-agent | aos-agent | 无（模型调用经 aos-egress） | 无 | seccomp |
| aos-view | aos-view | 只监听 127.0.0.1 | 静态资源（只读） | seccomp |
| ingress adapters | aos-ing-<name> | **无**（外部数据由 aos-egress 代取，见 §A6） | 无 | seccomp |

服务之间只通过 Unix socket 通信，每个 socket 的访问权限按"最少必要"配置。

---

## A6. 出口强制

这是版本 A 最关键的一节。

- 使用 nftables 设置 `OUTPUT` 链默认 **drop**，只放行 `skuid aos-egress` 的出站流量。回环接口只开放给声明过的本地端口。
- DNS 解析同样只由 aos-egress 完成，其余进程没有可用的解析器。
- 作业沙箱和适配器进程运行在**没有网络接口**的网络命名空间里。
- **入口也经由 aos-egress 取数**（核心 §10）：适配器只能向 aos-egress 提交取数请求，走通道 `fetch:<source>`，由常设规则覆盖（例如对已登记数据源自动放行）。取回的字节交给入口网关打标签。
- aos-egress 执行出口前 MUST 重新计算载荷哈希（核心 §11.4）。
- TLS 由 aos-egress 统一负责，使用 rustls。外部服务的凭据（API key、S3 密钥）只保存在 aos-egress 的密钥区，并按通道加密存储；agent 和适配器都拿不到明文凭据。

---

## A7. 存储布局

```
/aos/log/segment-000001.log ...   只追加段文件，每段 256 MiB，带 CRC
/aos/log/HEAD                     当前段与 seq，双写 + fsync
/aos/cas/sha256/ab/cd/<hash>      内容寻址 blob（分块）
/aos/index/objects.sqlite         对象当前版本、反向引用、分支覆盖层索引
/aos/keys/                        aos-confirm 与 aos-egress 的密钥区（各自可读）
```

- 文件系统使用 ext4（或 btrfs），数据分区必须启用写屏障。
- 提交事务时，先 fsync 日志段，再更新索引。索引任何时候都 MUST 能从日志完整重建（启动时提供 `--rebuild-index` 选项）。
- 宿主共享文件夹挂载在 `/aos/import/<name>`，只读，只有宿主文件夹适配器能访问。

---

## A8. 动作与作业

- **动作**：在 `aos-runtime` 里用 wasmtime 执行。每个调用设置 fuel 上限和内存上限。宿主 ABI 按核心 §8.4 实现。
- **本地作业**：
  - 每个作业放进一个 bubblewrap/nsjail 沙箱：无网络、只读挂载输入 blob、可写的只有临时输出目录，并用 cgroup 限制 CPU 和内存。
  - Python 环境预装在镜像里并固定版本（PyTorch CPU 版、ONNX、ONNX Runtime、numpy、Pillow）。作业**不能**在运行时安装包。
  - 作业结束后，`aos-jobs` 把输出目录里的文件写入 CAS，并按作业声明的输出类型创建对象，写入任务分支。
- **训练代码**来自 Git 适配器导入的某个提交，作为 blob 只读挂载进沙箱。

---

## A9. 人的界面与 iPhone 连接

- kiosk 浏览器显示 `aos-view`。为了开发方便，`aos-view` MAY 通过端口转发让宿主机浏览器也能访问。核心规格本来就把屏幕视为不可信，所以这样做不削弱安全性。
- **iPhone 连接**：
  - QEMU user 模式网络下，mDNS 无法穿透 NAT，因此配对二维码 MUST 直接包含宿主机的局域网 IP 和转发端口。
  - `run-aos.sh` 负责探测宿主机局域网 IP，转发 `confirm_port`，并把 IP 和端口写入虚拟机能读取的配置。
  - iPhone 与宿主机需在同一 Wi-Fi 下。

---

## A10. 平台安全测试（在完整虚拟机镜像上运行）

| 编号 | 测试 | 期望结果 |
|---|---|---|
| S1 | 以 aos-agent、aos-runtime、作业沙箱、各适配器的身份分别尝试建立 TCP/UDP 出站连接、做 DNS 查询 | 全部失败 |
| S2 | 作业沙箱尝试读取 `/aos/keys`、`/aos/log` | 失败 |
| S3 | WASM 动作尝试越权调用宿主 ABI | 事务中止，并写入 ActionViolation |
| S4 | 篡改 `/aos/log` 中任意一个字节后重启 | 检测到哈希链断裂，进入只读安全模式 |
| S5 | 删除 `objects.sqlite` 后重启并重建索引 | 状态与删除前一致 |
| S6 | 审批通过后替换出口载荷 | aos-egress 拒绝执行 |
| S7 | release 构建中尝试启用开发确认器 | 无法启用 |
| S8 | 拔掉虚拟网卡后执行带出口的任务 | 内部部分照常完成；出口失败并作为对象写回 |
| S9 | 在任务执行过程中强制关闭虚拟机，然后重启 | 日志一致；未完成的事务不生效 |

---

## A11. 里程碑

| 里程碑 | 内容 | 验收 |
|---|---|---|
| A-0 | 容器开发模式：核心 M0–M3 跑在容器里 | 核心一致性套件中 M0–M3 对应的部分 |
| A-1 | mkosi 镜像能在 QEMU 中启动并进入 kiosk 空白页 | 截图（仅用于开发验证）+ 启动日志 |
| A-2 | 服务拆分、用户隔离、nftables 出口强制 | S1、S2、S6 |
| A-3 | 存储持久化与崩溃恢复 | S4、S5、S9 |
| A-4 | 核心 M4–M5 在虚拟机内运行，人的界面可用 | 对等覆盖率达到 100% |
| A-5 | ML 提供方、适配器、本地作业沙箱 | E2E-ML（开发确认器） |
| A-6 | iPhone 配对与审批，经端口转发连接 | 真机完成 E2E-ML 的确认步骤；S7 |
| A-7 | 一周回放与指标 | 核心 §16.3 达标 |

---

## A12. 风险

| 风险 | 缓解 |
|---|---|
| kiosk 浏览器在 virtio-gpu 上性能差 | 降级为宿主机浏览器访问（安全性不受影响） |
| CPU 训练太慢，影响 E2E 测试 | E2E 使用极小的合成数据集；完整演示放在夜间运行 |
| 端口转发和局域网环境复杂（公司网络隔离） | v2 提供中继传输；v1 在 `DECISIONS.md` 里记录已验证可用的网络环境 |
| 出口强制有遗漏（例如 IPv6、raw socket） | S1 覆盖 IPv4、IPv6、UDP、raw socket；seccomp 禁止创建 raw socket |
