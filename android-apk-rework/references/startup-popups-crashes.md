# 启动、弹窗、签名自校验和闪退

用于开屏等待、公告/推荐遗漏或修改版启动异常。

## 独立推荐与广告入口

分别定位配置、响应、缓存、模型、定时器、展示和外链。非 nullable 集合用类型正确的空列表，nullable 广告对象可进入已有空分支；共享解析器可能也用于非广告业务，不能全局清空所有列表。

软件推荐可能是独立服务，组合应用/图片推广，并保存不同缓存。文本可来自服务器。`app_shu`、`app_heng`、推荐服务、bottom sheet/dialog 和首页 ready 回调只是线索，不是固定协议。

专用入口返回应正常完成 Future，释放“正在展示”状态；不能删调用却留下等待、遮罩和阻塞标志。广告列表清空之后仍检查独立弹窗调度。

测试冷启动、新配置与已有缓存的覆盖安装，不自动清除用户设备数据。

推荐也可能通过独立 `recommend-app/pageList` 一类请求重新填充列表，原广告消费者改为空列表不会覆盖它。追踪具体字段及加载函数：在原缓存清空之后、专用请求之前转到本函数已有刷新/异步完成路径，可同时覆盖旧缓存与新填充；保留 loading/ready 的正常结束。路径及字段名只是线索，按当前样本确认。

缓存测试用空及多个非空列表，核查原对象、长度清零、刷新次数和 Future 完成；运行测试检查实际推荐位/关闭节点，而非只看服务返回为空。多个集合、首页弹窗调度与播放前广告倒计时分别验证，不用一个结果代替全部去广告验收。

## 取消等待，保留完成条件

先追踪配置/线路、账号、所需首页缓存、就绪/错误标志与导航。“成功流程中某个 await 完成”不等于全部初始化完成。原 Timer 可能在创建后等待另一个 `Future.then` 设置 ready；同步导航可能提前 dispose 控制器。

可在原函数内取消额外等待，在原 ready 回调导航，或保留短周期回调。轮询方案确认：ready=false 不会快速递减并取消；zero-period 不造成忙循环；error/retry/dispose 不产生重复 Timer 或多次导航；广告列表空/非空行为符合需求。

本次保留原回调与路由帧，用已有 100ms Duration，未就绪直接返回等待。这个数值是案例选择，不固定用于其他应用。

## 签名自校验同步

重新签名前读 Manifest 注册的 provider、Application 与 native 初始化。搜索：

```text
ContentProvider.onCreate / Application.attachBaseContext
PackageInfo.signatures / SigningInfo
SHA-256 / Base64 / EXPECTED_CERT / checkSignature
Process.killProcess / System.exit / Runtime.exit
```

Android 安装签名有效与应用接受证书是不同检查，后者可在 Flutter 初始化前结束进程。同步已确认的预期证书值，保留不相关检查；其他拦截按当前请求及证据处理。

如果计算的是 `SHA256(certificate DER bytes)` 后用 Base64 比较，按实际签名证书摘要转换，不能计算 APK/密钥文件摘要或十六进制文本的 Base64：

```python
import base64
expected_b64 = base64.b64encode(bytes.fromhex(certificate_sha256_hex)).decode('ascii')
```

多签名、证书历史、native 或其他算法/编码按实际实现处理。

无法同步硬编码值时，定位检查方法的调用方和失败副作用，在当前需求范围内调整该检查结果或失败分支，保留后续初始化。先确认校验结果是否还用于密钥派生、资源解密或其他状态；简单返回成功可能仍导致下游失败。区分证书摘要、DEX/SO 内容摘要及整包校验，修改一处常量不代表覆盖所有入口。客户端自校验的修改也不证明服务端完整性判定已通过。

## DEX 的非直观失败

DEX 存在排序约束和多处索引。等长替换证书字符串并重算 SHA1/Adler32，仍可能让表失序。ART 报 `Out-of-order string_ids`，随后可能表面显示 `Unable to get provider` 或 `ClassNotFoundException`，实际是整个 DEX 被拒绝。

修改指定 Smali 字段/方法，重新组装相关 DEX，让 assembler 重建排序与索引。只替换对应 `classes*.dex`；再反编译按类/方法比对预期差异，并检查构建/ART 日志。Header checksum 通过不代表结构有效。

Apktool 的 `-r` 可避免不需要的资源反编译，`b --no-apk` 可获得重建文件而不重打整包；以本机版本为准：[Apktool 官方参数](https://apktool.org/docs/cli-parameters/)。

## 故障分流

在获准设备或隔离模拟器保存失败日志，再清缓冲做对照，显式指定 serial：

```powershell
& $apkAdb -s $apkSerial logcat -d -b crash
& $apkAdb -s $apkSerial logcat -d -t 500
& $apkAdb -s $apkSerial shell am start -n 'package.name/activity.name'
```

| 观察 | 下一步 |
| --- | --- |
| 很快 killProcess/SIG9，没进入 Flutter | 查 provider/Application 自退出；SIG9 不能唯一证明证书问题 |
| ART 拒绝 DEX或类找不到 | 查抑制异常和 dexopt 日志，检查排序、结构、加载路径 |
| VerifyError/Java 异常 | 查寄存器、类型、引用及异常范围 |
| Dart 类型/空值/late 错误 | 查值类型、nullable 分支和初始化顺序 |
| 进程存活但 Unhandled Exception 含认证错误 | 保存实际错误和阶段；同环境对照原包访客流程，单独报告服务端异常 |
| native SIGSEGV/栈异常 | 查边界、分支、软件栈、写屏障及 VM 栈图 |
| x86 ARM 翻译层 SIGILL，原版也失败 | 记录限制，换兼容环境/真机，不靠修改无关渲染逻辑掩盖 |

针对同一触发重测。缺真机不妨碍修正版构建，但保留未完成的运行验证项。

日志中的 `Unhandled Exception` 计数不能直接等同崩溃；`pidof` 成功也不能等同所有功能正常。分别记录原生崩溃、DEX/字段/类型错误、服务端认证错误和目标功能的表现。UI 与日志的 PID/前台归属及诊断包恢复方法见 [isolated-diagnostics.md](isolated-diagnostics.md)。
