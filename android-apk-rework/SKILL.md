---
name: android-apk-rework
description: 分析并修改现有 Android APK，适用于反编译、去广告、客户端 VIP/金币/试看权限修改、启动倒计时与公告或软件推荐弹窗处理、重打包签名，以及修改版签名自校验退出和闪退排查。覆盖 Java/Smali、Flutter/Dart AOT 与原生 SO；不用于普通 Android 源码开发或仅安装使用应用。
---

# 安卓 APK 逆向修改

目标是交付可追溯、可安装的修改版 APK，并明确哪些行为已经验证。根据当前请求选择修改范围，不把历史样本的地址、会员等级、寄存器约定或签名信息套到新 APK。

## 输入与工作目录

明确输入 APK、目标行为和输出目录。已有会话授权和要求继续有效；先完成可独立进行的分析，只在缺少必要信息时询问。用户反馈闪退时，尽早确认退出发生在启动页、首页还是播放阶段，同时继续查代码。

保留原包，每个 APK 使用独立工作目录。将原包 SHA256、包名、版本、ABI、Dart/Flutter 版本、工具版本和签名证书摘要保存为清单。已有修改版作为对照，不替代原始分析基线。修正版本单独输出，避免混淆旧包与新包。

建议目录：`input/`、`work/<sample>/`、`output/<revision>/`，可按用户指定位置调整。

可用 [scripts/apk_workbench.py](scripts/apk_workbench.py) 执行清单、受校验补丁和包内比对；命令与格式见 [references/packaging-validation.md](references/packaging-validation.md)。脚本不自动发现权限判断，不签名，也不证明运行正确。

## 先定位实现层

| 观察 | 分析入口 |
| --- | --- |
| 业务逻辑在 `classes*.dex` | JADX 阅读控制流，Apktool/Smali 修改、重新组装相关 DEX |
| `libflutter.so`、`libapp.so`、Flutter assets | 先查 Android 外壳，再做 AOT 分析；读 [references/flutter-aot.md](references/flutter-aot.md) |
| 业务在其他原生 SO | ELF 段、架构、符号、交叉引用与反汇编，必要时动态观察 |
| Unity、React Native、加固壳、split APK | 按实际实现继续定位，不强行视为 Dart 或 Smali 业务 |

同一 APK 可能同时需要修改 Android 启动层和 Flutter 业务层。看到 Flutter 不代表可以跳过 DEX：本次真实故障发生在 `ContentProvider` 启动签名检查。

## 交付前先查签名与启动自校验

计划重新签名时，提前搜索 `IntegrityProvider`、`ContentProvider.onCreate`、`Application`、`checkSignature`、`EXPECTED_CERT`、`MessageDigest`、`killProcess`、`System.exit` 及相关 native 入口。

确认校验对象、摘要算法、编码和失败行为。如果退出由预期证书与修改版签名不一致导致，优先同步当前修改版证书的预期值，保留不相关检查。只有明确定位到其他拦截且属于当前请求时，才选择相应分支修改，不全局清空所有安全检查。

DEX 常量修改通过 Smali 重新组装。**字符串等长替换并修复 checksum，仍可能破坏 `string_ids` 排序，导致 ART 拒绝加载整个 DEX。** 详见 [references/startup-popups-crashes.md](references/startup-popups-crashes.md)。

## 从目标行为追踪到数据与判断

按当前需求选择以下分支；广告、启动、公告与推荐细节读 [references/startup-popups-crashes.md](references/startup-popups-crashes.md)。

- **广告**：追踪配置/响应、模型解析、缓存恢复、调度、展示与外链，优先在共享数据入口或专用展示入口处理。保留符合原类型的空列表、nullable 值或异步完成路径。检查开屏、首页、播放器、横幅、软件推荐及图片推广，避免只隐藏组件而留下遮罩和等待。
- **VIP 与视频权限**：追踪用户状态、列表/详情模型、真实权限谓词、播放地址响应、试看计时和暂停分支。区分“允许播放”“需要购买”“处于试看”的 bool 语义，按调用方判断返回值。最高等级须由枚举/比较逻辑等证据确认；无法确认时说明实际修改值。服务器拒绝完整资源、令牌或授权，不当作本地解锁成功。
- **开屏等待**：画清必要初始化、就绪/错误状态、广告/倒计时和导航的顺序。仅取消额外等待，不提前销毁控制器或越过尚未完成的初始化。缩短轮询时检查未就绪分支是否递减计数、提前取消或忙循环。
- **入场公告与软件推荐**：分别查公告服务、推荐服务和缓存入口。文本可能来自服务器，结合模型、路由和弹窗创建定位。覆盖冷启动及覆盖安装后的缓存触发场景。

## 实施最小且可审查的修改

每个补丁记录 APK SHA256、ZIP 成员、VA/文件偏移、原始与修改后字节/指令、字段类型、调用方依据、目的及验证方式。先校验原始内容；失配就停止该补丁并重新定位，不猜相邻地址。

原生/AOT 修改用 ELF `PT_LOAD` 将 VA 映射到文件偏移，确认目标在文件实际包含的段内。保持指令边界和长度，检查分支距离、栈帧、返回类型、异步完成、对象布局和 GC 写屏障。Smali 修改检查寄存器、参数、异常范围和返回类型。

相同名称或界面不代表相同实现。多个解析器、不同页面模型、缺字段分支或多个 ABI 逐一判断是否属于当前范围。大文件及单行 JSON 应结构化读取，不输出完整字符串表或函数索引。

## 重打包、签名与验证

按 [references/packaging-validation.md](references/packaging-validation.md) 完成检查并记录实际结果：

1. 包内改动仅限声明成员与重新签名文件，资源、Manifest、其余 DEX/SO 没有无意改动。
2. 原生补丁重新反汇编；DEX 重新反编译比对，确认范围与可加载性。
3. `zipalign` 后再 `apksigner`，最终包检查对齐、签名并记录 SHA256/证书摘要。ZIP 对齐不等于 ELF 满足 16KB 页面兼容要求。
4. 对脆弱的权限谓词、字段存储、初始化就绪/未就绪、分支与栈恢复运行有意义的检查。Unicorn 的 VM/路由桩只证明被检查的指令行为。
5. 在可用 Android 环境测试安装、冷启动、同签名覆盖启动、受影响弹窗及播放。缺设备时完成静态与包检查，如实标注未验证场景。

异常先保存日志并定位退出阶段，在同一环境对照原版与修改版。ABI 翻译层的共同崩溃不能证明补丁错误或手机正常；按 [references/startup-popups-crashes.md](references/startup-popups-crashes.md) 分流。

修正反馈时保留正常功能，更新受影响补丁与验证。已通过且未受影响的检查无需无理由重复，不通过删除必要初始化来掩盖故障。

## 交付

给出最终签名 APK 的绝对路径链接、具体修改、验证范围和剩余限制。沿用会话内已有修改版密钥，密钥不放入技能、报告或分享压缩包。没有原版密钥时，说明通常无法覆盖官方版本；卸载用户设备原版不由构建任务自动授权。

保留补丁清单、包比对、签名日志和必要故障证据，不把 CRC/签名通过说成全部运行通过。全过程与纠错依据见 [references/case-study.md](references/case-study.md)。
