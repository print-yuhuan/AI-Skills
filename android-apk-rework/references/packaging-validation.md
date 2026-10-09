# 工具、补丁格式、打包与验证

## 工具发现

复用 Java、Android SDK Build Tools、ADB、Apktool、JADX 和按需的 ELF/反汇编工具，记录版本，不写死本次安装位置。普通 Python helper 只需标准库；AOT 分析可另用 Capstone/pyelftools/Unicorn。

多包可共用工具和密钥，分析及补丁独立。静态读取可并行；修改、打包、签名、验证按依赖顺序执行。

## 反编译与重组模板

变量均由当前工具发现结果和工作目录设置，命令退出非零时先读日志，不能继续交付：

```powershell
& $apkAapt2 dump badging $apkSource
& $apkSigner verify --verbose --print-certs $apkSource
& $apkJadx -d $apkJadxDir $apkSource
& $apkJava -jar $apkToolJar d $apkSource -r -o $apkDecodeDir
# 修改已定位的 smali 后，仅重建；读取实际 build 输出的 classes*.dex。
& $apkJava -jar $apkToolJar b $apkDecodeDir --no-apk
if ($LASTEXITCODE -ne 0) { throw 'DEX rebuild failed' }
```

JADX 的 Java 输出用于理解控制流，遇到反编译失败回查 Smali；不把它直接编译回包。[JADX 官方用法](https://github.com/skylot/jadx)。只改 DEX 时避免资源重建，用 replacement 放回声明 DEX；确需修改 Manifest/资源时正常解码重建，并将相关成员纳入变更清单。`--no-apk` 是否可用以工具版本为准，[Apktool 官方参数](https://apktool.org/docs/cli-parameters/)。新目录无需强制覆盖已有分析结果。

## 通用 helper

路径按当前项目设置，下面在技能目录运行：

```powershell
python -X utf8 scripts/apk_workbench.py inventory --input 'C:/work/apks' --out 'C:/work/inventory.json'
python -X utf8 scripts/apk_workbench.py build --source 'C:/work/original.apk' --spec 'C:/work/spec.json' --out 'C:/work/app-unsigned.apk' --manifest 'C:/work/patch-manifest.json'
python -X utf8 scripts/apk_workbench.py compare --source 'C:/work/original.apk' --target 'C:/work/app-final.apk' --manifest 'C:/work/patch-manifest.json' --out 'C:/work/comparison.json'
```

`inventory` 读取文件或目录第一层 APK，记录摘要、CRC、ABI、库架构、DEX 与可能实现层，不读取二进制 Manifest。用 aapt2 补齐包名/版本/SDK/启动 activity，apksigner 读取原证书。

`build` 要求当前 APK SHA256 匹配 specification，原生字节 guard 匹配且不重叠。只对 SO 做原地字节补丁，DEX/其他成员通过整体 replacement；输出已存在就停止。保留 ZIP 属性，剔除失效 JAR 签名并生成清单，尚未对齐或签名。

```json
{
  "source_sha256": "当前原包的SHA256摘要（64个十六进制字符）",
  "patches": [
    {
      "entry": "lib/arm64-v8a/libapp.so",
      "va": "0x当前分析得到的VA",
      "before_hex": "原始指令字节",
      "after_hex": "等长修改字节",
      "purpose": "当前目标、类型依据和调用方行为"
    }
  ],
  "replacements": [
    {
      "entry": "classes.dex",
      "file": "rebuilt/classes.dex",
      "expected_sha256": "原DEX成员的SHA256摘要",
      "purpose": "Smali重新组装的已定位修改"
    }
  ]
}
```

这是填写格式，不能直接执行，不用的数组可省略。`offset` 可代替 `va`，两者只指定一个；VA 用 ELF32/64 PT_LOAD 映射，不自动验证指令语义。replacement 路径相对 spec 文件，DEX header 校验之后仍需 assembler/ART 和语义比对。

`compare` 验证清单绑定原包，检查 CRC，声明成员匹配新摘要，其余有效载荷一致，旧 JAR 签名可移除、新 JAR 签名可添加。它不验证签名块、ZIP/ELF 对齐或运行。

## 签名流水线

SDK 支持时，SO 的 ZIP 页面布局可用 `-P 16`；不能修复 SO 内部 PT_LOAD 的不兼容对齐。[Android zipalign 文档](https://developer.android.com/tools/zipalign)。

用 apksigner 时先对齐后签名，之后修改包内容会使签名失效。[Android apksigner 文档](https://developer.android.com/tools/apksigner)。

```powershell
& $apkZipalign -P 16 -f 4 'app-unsigned.apk' 'app-aligned.apk'
if ($LASTEXITCODE -ne 0) { throw 'zipalign failed' }
& $apkSigner sign --ks $apkKeystore --ks-key-alias $apkKeyAlias --ks-pass env:APK_KS_PASSWORD --key-pass env:APK_KEY_PASSWORD --out 'app-final.apk' 'app-aligned.apk'
if ($LASTEXITCODE -ne 0) { throw 'sign failed' }
& $apkSigner verify --verbose --print-certs 'app-final.apk'
if ($LASTEXITCODE -ne 0) { throw 'signature verification failed' }
& $apkZipalign -c -P 16 4 'app-final.apk'
if ($LASTEXITCODE -ne 0) { throw 'alignment verification failed' }
```

按已有设置提供路径/密码，不写进 Skill/报告。需要时 Java 直接调用 `lib/apksigner.jar`，Python subprocess 传参数数组，避免 `.bat` 和中文路径的 shell 拼接问题。签名方案按 minSdk/平台决定，不盲目强制所有方案。

没有现成修改版密钥时创建独立重签名密钥，记录 alias 和证书摘要，妥善保存用于后续覆盖安装；不要每次修正都生成新密钥。私钥和密码不随 APK、补丁清单或技能压缩包交付。

## 证据与安装

记录原包/最终包摘要、包名/版本、证书、清单与签名结果，分别检查 ZIP 页面布局及 ELF 段布局，不仅靠 zipalign 宣称支持 16KB 设备。

| 证据 | 能说明什么 |
| --- | --- |
| 字节 guard/反汇编 | 目标匹配且形成预期指令 |
| DEX header/重反编译 | 基础一致性和声明语义，仍需 ART |
| CRC/有效载荷比对 | 可解压、变更符合清单 |
| 签名/对齐 | Android 签名与 ZIP 布局通过 |
| 指令模拟 | 指定输入与 mock 范围的分支、存储、栈行为 |
| 安装/启动 | 当前环境相应阶段的实际表现 |
| 连续播放/重启/缓存 | 当前资源及具体场景的运行表现 |

同修改版密钥通常支持同包名覆盖，还受版本、签名历史、设备管理和数据兼容等条件影响。不自动卸载用户设备原版或通过降级/清数据进行普通验证。

客户端放行不保证服务端会员、下载额度、金币、令牌或完整资源改变，单独报告这些结果。
