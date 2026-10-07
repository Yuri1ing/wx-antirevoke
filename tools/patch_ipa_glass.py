#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
把微信 IPA 里的「旧设计兼容模式」开关去掉，让系统在 iOS 26 上
为这个 App 启用真正的液态玻璃。

背景
----
微信 8.0.79 的 Info.plist 里声明了：

    UIDesignRequiresCompatibility = true

这个 key 的意思是「请按 iOS 18 的外观体系渲染我」。它确实是微信用
iphoneos26.1 SDK 编译的，但主动选择了兼容模式 —— 代价是系统在整个
App 内禁用液态玻璃，所有 UIGlassEffect 一律渲染成全透明。

删掉这个 key，系统就会按 iOS 26 新设计渲染，UIGlassEffect 随之生效。

代价（务必知悉）
----------------
这会改变**整个微信**的外观，不只是底栏：按钮、列表、弹窗、搜索框等
都会切成 iOS 26 的新设计。微信自己并没有为新设计做适配，所以存在
布局错位甚至崩溃的可能。插件里已经写了分流逻辑：检测到这个 key 在
就用 UIBlurEffect（毛玻璃）兜底，检测不到才用真正的 UIGlassEffect。
所以这个脚本是可逆的 —— 换回原 IPA 即恢复。

用法
----
    python patch_ipa_glass.py <原始.ipa> [输出.ipa]

输出文件名默认是「原名_glass.ipa」。
"""

import os
import plistlib
import sys
import zipfile

# 要去掉的 key。只删这一个，其余原样保留。
KEYS_TO_REMOVE = ["UIDesignRequiresCompatibility"]


def find_info_plists(zf):
    """找出 Payload 下所有 Info.plist（主 App 和 Watch 都要处理）。"""
    return [n for n in zf.namelist() if n.endswith(".app/Info.plist")]


def patch_plist(data):
    """返回 (新数据, 是否改动, 删掉的 key 列表)。"""
    try:
        plist = plistlib.loads(data)
    except Exception as exc:                      # noqa: BLE001
        return data, False, [], f"解析失败：{exc}"

    removed = []
    for key in KEYS_TO_REMOVE:
        if key in plist:
            del plist[key]
            removed.append(key)

    if not removed:
        return data, False, [], None

    return plistlib.dumps(plist, fmt=plistlib.FMT_BINARY), True, removed, None


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    src = os.path.abspath(sys.argv[1])
    if not os.path.isfile(src):
        print(f"❌ 找不到文件：{src}")
        return 1

    if len(sys.argv) >= 3:
        dst = os.path.abspath(sys.argv[2])
    else:
        base, ext = os.path.splitext(src)
        dst = base + "_glass" + ext

    if os.path.exists(dst):
        print(f"❌ 输出文件已存在，先删掉或换个名字：{dst}")
        return 1

    src_size = os.path.getsize(src)
    print(f"源文件：{src}")
    print(f"大小  ：{src_size / 1024 / 1024:.1f} MB")
    print(f"输出  ：{dst}")
    print()

    with zipfile.ZipFile(src) as zin:
        targets = find_info_plists(zin)
        if not targets:
            print("❌ IPA 里没找到 Info.plist，结构可能不对")
            return 1

        print("将处理以下 Info.plist：")
        for t in targets:
            print(f"  - {t}")
        print()

        # 先把要替换的内容准备好，再决定哪些条目要改写
        replacements = {}
        for t in targets:
            new_data, changed, removed, err = patch_plist(zin.read(t))
            if err:
                print(f"⚠️  {t} {err}")
                continue
            if changed:
                replacements[t] = new_data
                print(f"✅ {t}")
                print(f"   删除：{', '.join(removed)}")
            else:
                print(f"⏭  {t} 本来就没有这个 key，跳过")

        if not replacements:
            print("\n❌ 所有 Info.plist 里都没有需要删除的 key，无需修改")
            return 1

        print(f"\n开始重新打包（{len(zin.namelist())} 个条目）...")
        total = len(zin.namelist())
        with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zout:
            for i, item in enumerate(zin.infolist(), 1):
                if item.filename in replacements:
                    # 保持原有的压缩方式和时间戳
                    zout.writestr(item, replacements[item.filename])
                else:
                    # 逐条转储，避免一次性把整个 400MB 读进内存
                    with zin.open(item) as fsrc:
                        zout.writestr(item, fsrc.read())
                if i % 2000 == 0 or i == total:
                    pct = i * 100 // total
                    print(f"  {pct:3d}%  ({i}/{total})", flush=True)

    print(f"\n✅ 完成：{dst}")
    print(f"   大小：{os.path.getsize(dst) / 1024 / 1024:.1f} MB")
    print()
    print("接下来：")
    print("  1. 用轻松签把这个 IPA 和插件 dylib 一起注入并签名")
    print("  2. 装上后底栏应该出现真正的液态玻璃")
    print("  3. 同时留意微信其它界面有没有错位 —— 如果问题严重，")
    print("     换回原始 IPA 即可（这个脚本不改原文件）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
