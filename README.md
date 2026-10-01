# 微信防撤回插件（iOS 8.0.75 · 非越狱自签版）

一个只做一件事的微信插件：**防撤回**。目标环境是**非越狱设备 + 轻松签注入 + 自签/TrollStore 安装**。

> ## ⚠️ 动手前请先读这段
>
> **1. 账号风险（最需要重视的一条）**
> 微信内置了完整性/环境校验体系：`MMRuntimeIntegrity`（含 `auditLoadedImages`）、
> `MMSecurityPolicyValidator`（`verifyCodeSignature:`）、`CUtility`
> （`validateCertChain:` / `getAppBundleSignatureHash` / `integrityHash`）、
> `MMAntiTamperGuard`，以及 `MMTokenService`（`reportCrashLog:type:` 等）。
> 关键点是：**这些检测结果会经独立通道上报服务端走风控，不是本地弹窗那么温和。**
>
> 重签名 + 注入 dylib 必然动到签名摘要，也会让 `auditLoadedImages` 多看到一个
> 非系统镜像。**建议先在小号上验证，不要拿主力账号做第一个实验对象。**
>
> **2. 闪退风险**
> 最常见的三个原因：IPA 没砸壳、dylib 架构与主二进制不匹配、
> 签名工具本身不兼容。真机验证前先在测试机上跑。
>
> **3. 合规**
> 修改微信客户端可能违反其服务协议。本项目仅供个人学习研究。

---

## 一、为什么不能直接用 GitHub 上那些老项目

调研结论（截至 2026-10）：

| 项目 | 平台 | 最后更新 | 问题 |
|---|---|---|---|
| [sunnyyoung/WeChatTweak](https://github.com/sunnyyoung/WeChatTweak) | **macOS** | 2026-02 | 平台不对，且已转型为二进制字节补丁 |
| [sunnyyoung/WeChatTweak-iOS](https://github.com/sunnyyoung/WeChatTweak-iOS) | iOS | 已 archived | 文件树里根本没有防撤回 |
| [itenfay/WeChat_tweak](https://github.com/itenfay/WeChat_tweak) | iOS | 2024-06 | 用 iOSOpenDev 老工具链，hook 点已失效 |
| [kelvinhongkjy/WeChat-DenyRevocation](https://github.com/kelvinhongkjy/WeChat-DenyRevocation) | iOS | — | hook `DelMsg:MsgList:DelAll:`，会连带干掉「主动删消息」 |
| [Lorwy/WeChatPri](https://github.com/Lorwy/WeChatPri)、[tuxi/WeChatExtensions](https://github.com/tuxi/WeChatExtensions) | iOS | 2018 | 严重过时 |
| [huiyadanli/RevokeMsgPatcher](https://github.com/huiyadanli/RevokeMsgPatcher) | **Windows PC** | 2026-08 | 平台不对，但思路可参考 |

**没有任何公开 iOS 项目声明支持微信 8.0.5x 及以上。**

### 本项目实测出来的关键事实

我把你的 `微信_8.0.75.ipa` 解出主二进制（503.8 MB，未加密）做了完整解析，
拿到 **43394 个类 / 594370 个方法名**的真实映射。结论推翻了流传最广的说法：

| 流传的 hook 点 | 8.0.75 实测 |
|---|---|
| `CMessageMgr -onRevokeMsg:` | ❌ **不存在**。类还在（348 个方法），但没这个方法 |
| `MessageService -RevokeMsg:` | ❌ 任何原文里都没出现过，属以讹传讹 |
| `CMessageMgr -HandleRevokeMsg:` | ❌ 不存在 |

**8.0.75 真实存在的是另一套：**

| 类 | 方法 | 类型编码 |
|---|---|---|
| `MessageRevokeMgr` | `-onRevokeMsg:` | `v24@0:8@16` |
| `MessageBatchRevokeMgr` | `-onRevokeMsg:` | `v24@0:8@16` |
| `MessageRevokeMgr` | `-replaceRevokedMsg:` | `v24@0:8@16` |
| `MessageRevokeMgr` | `-batchReplaceRevokedMsg:` | `v24@0:8@16` |

插件默认拦截这四个入口（前两个是入口，后两个是执行「替换成撤回提示」的动作，互为兜底）。


---

## 二、稳定性设计（为什么它不容易闪退）

| 设计 | 作用 |
|---|---|
| 不链接 CydiaSubstrate / ellekit / fishhook | 非越狱设备没有 substrate，链了它必然加载失败。改为只用 ObjC runtime 自带的 `method_setImplementation` |
| 只替换「本类自己定义」的方法 | 用 `class_copyMethodList` 精确匹配，绝不通过父类命中，避免污染继承链上的其它逻辑 |
| 多轮延迟重试 | 微信有些控制器是懒加载的，分 0/1/3/6/12/20 秒六轮尝试 |
| 显式校验 bundle id | 只有 `com.tencent.xin` 才启用，误注入不产生影响 |
| 全程异常隔离 | 任何一步失败只写日志并跳过，不抛异常 |
| 不 Hook 任何 UI / 网络方法 | 只碰撤回处理入口这一个点 |

---

## 三、使用流程

### 步骤 1：准备微信 IPA

**必须是砸壳（解密）过的 IPA。** App Store 直接下载的原版 IPA 有 FairPlay 加密，
注入重签名后通常无法运行。

砸壳包的常见来源：自己的旧设备用 `frida-ios-dump` / `Clutch` 导出，
或第三方已解密的 8.0.75 包。

把 IPA 放到本目录的 `ipa/` 文件夹里。

### 步骤 2：hook 点（已完成，无需重做）

**这一步已经做完了。** 我用 `tools/analyze_wechat.py` 解析了你那份 8.0.75 IPA，
把真实存在的方法名填进了 `tweak/AntiRevoke.m` 的 `kCandidates`。

如果你想自己复核，或者将来微信升级后要重新定位：

```bash
# 第一步：解析 IPA，导出全部类与方法（结果会缓存，第二次秒开）
python tools/analyze_wechat.py ipa/微信_8.0.75.ipa --dump-classes build/classes.txt

# 第二步：查具体某个类有哪些方法
python tools/query_classes.py build/classes.txt MessageRevokeMgr

# 或者全局找哪些类有某个方法
python tools/query_classes.py build/classes.txt --sel "onRevokeMsg:"
```

> 如果脚本报告「二进制被加密、ObjC 元数据不可读」，说明用的是未砸壳的包，需要先砸壳。
> 你这份 8.0.75 是**未加密**的，解析完全正常。

### 步骤 3：编译 dylib

**方式 A：GitHub Actions（推荐，本机零配置）**

1. 把整个 `wx-antirevoke` 文件夹推到一个 GitHub 仓库
2. 打开仓库的 **Actions** 标签，workflow 会自动运行
3. 跑完后在 **Artifacts** 里下载 `wxantirevoke-dylib`，解压得到 `wxantirevoke.dylib`

**方式 B：本机 macOS**

```bash
./build.sh                 # 默认只编 arm64
ARCHS="arm64 arm64e" ./build.sh
```

编完检查一下 `otool -L` 的输出，**里面不应该出现 substrate**。

### 步骤 4：用轻松签注入

1. 轻松签 → 导入你的微信 IPA
2. 在签名设置里找到「**注入 dylib** / 注入插件」入口，添加 `wxantirevoke.dylib`
3. 用自己的证书签名，安装到设备

> 不同版本的轻松签菜单位置不一样，认准「注入」这个功能即可。

### 步骤 5：验证

1. 打开微信，正常登录
2. 找个人给你发一条消息，然后让他在 2 分钟内撤回
3. **消息应该还在会话里**，同时不会出现「对方撤回了一条消息」

想看调试日志的话，文件在微信沙盒的
`Documents/wxantirevoke.log`（用轻松签的「应用文件管理」查看）。

---

## 四、排错

| 现象 | 原因 / 处理 |
|---|---|
| 微信启动直接闪退 | 大概率是 IPA 没砸壳，或 dylib 架构与主二进制不匹配。用 `lipo -info` 对比两者架构 |
| 微信正常但防撤回无效 | 候选方法名在 8.0.75 上变了。跑步骤 2 的分析，把新方法名填进候选表重新编译 |
| 日志里全是「类未注册」 | 同上，说明硬编码的类名在这个版本不存在 |
| 日志里出现大量 `🔍 候选` | 这是自动扫描的结果，用来人工找正确的 hook 点 |

---

## 五、目录结构

```
wx-antirevoke/
├─ tweak/
│  └─ AntiRevoke.m          # 插件本体（hook 引擎 + 候选表 + 自适应扫描）
├─ tools/
│  └─ analyze_wechat.py     # 离线 Mach-O / ObjC 分析工具
├─ build.sh                 # 调用 clang 交叉编译
├─ .github/workflows/
│  └─ build.yml             # GitHub Actions 自动编译
└─ ipa/                     # 放你的微信 IPA（不进版本库）
```

---

## 六、已知限制

- 拦截的是**本地**的撤回处理。服务端已经把消息标记为撤回，
  下次重新登录或从其它设备同步时，这条消息可能还是会消失。
- 只做防撤回，没有任何抢红包、改步数、伪造定位之类的功能。
- 不做越狱伪装。微信有个 `JailBreakHelper` 类
  （`+JailBroken` / `-IsJailBreak` / `-HasInstallJailbreakPlugin:` /
  `-HasInstallJailbreakPluginInvalidIAPPurchase`），老项目会把它全部 hook 成 NO。
  本插件刻意不碰它——伪装越狱状态属于额外的检测对抗，与本项目「只做防撤回」的
  定位不符，也会引入额外风险。
- 微信大版本升级后候选方法名可能失效，需要重新跑一次步骤 2。

---

## 七、调研依据

详细的调研过程、全部来源 URL、可信源码原文、版本矩阵，见
[docs/调研报告.md](docs/调研报告.md)。

核心事实（都有出处，非推测）：

- 目前**没有任何公开的 iOS 仓库声明支持微信 8.0.5x 及以上**；
  iOS 侧公开源码普遍停更在 2021–2024 年。
- 唯一取到完整原文的 iOS 防撤回实现是
  [itenfay/WeChat_tweak](https://github.com/itenfay/WeChat_tweak)，
  hook 的是 `%hook CMessageMgr / - (void)onRevokeMsg:(CMessageWrap *)arg1`。
- 坊间流传很广的 `CMessageMgr -HandleRevokeMsg:`、`MessageService -RevokeMsg:`、
  `WCRemoteMessage` 这些说法，**本次调研一个都没找到出处**。
- 仍然活跃的 `sunnyyoung/WeChatTweak` 是 **macOS** 项目，且早已转型为
  **二进制字节补丁**（直接把函数入口写成 `MOV W0,#0; RET`），不再 hook 方法名。
  它的版本号（微信 macOS 4.1.x）**不能**当作 iOS 8.0.x 的参考。
- 微信自身是否检测 Frida/ptrace：**没有找到证据**，本项目不据此做任何假设。
