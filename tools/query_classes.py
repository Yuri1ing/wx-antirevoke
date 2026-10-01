# -*- coding: utf-8 -*-
"""
从 analyze_wechat.py --dump-classes 导出的文件里查询类与方法。

用法:
    python query_classes.py <dump文件> <类名或子串>...
    python query_classes.py classes.txt --sel onRevokeMsg:      # 全局按方法名找
    python query_classes.py classes.txt --list                  # 列出类名
"""
import re
import sys
import os

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

if len(sys.argv) < 3:
    print(__doc__)
    sys.exit(1)

path = sys.argv[1]
args = sys.argv[2:]

print("读取 %s ..." % path)
classes = {}       # 类名 -> [(sel, types)]
order = []
cur = None
with open(path, "r", encoding="utf-8", errors="replace") as f:
    for line in f:
        if line.startswith("    - "):
            if cur is None:
                continue
            body = line[6:].rstrip("\n")
            sel, _, types = body.partition("  |  ")
            classes[cur].append((sel.strip(), types.strip()))
        elif line.strip():
            cur = line.strip()
            if cur not in classes:
                classes[cur] = []
                order.append(cur)

print("共 %d 个类\n" % len(order))

if args and args[0] == "--list":
    for c in order:
        print("  %s  (%d 个方法)" % (c, len(classes[c])))
    sys.exit(0)

if args and args[0] == "--sel":
    pat = args[1] if len(args) > 1 else "revoke"
    print("=== 拥有匹配 %r 的方法的类 ===" % pat)
    hits = 0
    for c in order:
        for sel, types in classes[c]:
            if pat.lower() in sel.lower():
                print("  %-50s -%s  [%s]" % (c, sel, types))
                hits += 1
    print("\n共 %d 条" % hits)
    sys.exit(0)

for want in args:
    exact = [c for c in order if c == want]
    fuzzy = [c for c in order if want.lower() in c.lower() and c not in exact]
    print("=" * 78)
    print("查询: %r   精确匹配 %d 个 / 模糊匹配 %d 个" % (want, len(exact), len(fuzzy)))
    print("=" * 78)
    for c in exact + fuzzy[:8]:
        ms = classes[c]
        print("\n▌%s  (%d 个方法)" % (c, len(ms)))
        for sel, types in ms:
            mark = "  <<<" if re.search(r"revoke|recall|undo", sel, re.I) else ""
            print("    - %-62s [%s]%s" % (sel, types, mark))
