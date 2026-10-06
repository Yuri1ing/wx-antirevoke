# -*- coding: utf-8 -*-
"""查 8.0.79：防撤回方法是否齐全 + 底部栏（TabBar）相关类。"""
import os
import re
import sys

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

DUMP = r"C:\Users\陈炜坤\Desktop\wx-antirevoke\build\classes-8.0.79.txt"

classes = {}
order = []
cur = None
with open(DUMP, encoding="utf-8", errors="replace") as f:
    for line in f:
        if line.startswith("    - ") or line.startswith("    + "):
            if cur is None:
                continue
            body = line[6:].rstrip("\n")
            sel, _, types = body.partition("  |  ")
            classes[cur].append((line[4], sel.strip(), types.strip()))
        elif line.strip():
            cur = line.strip()
            if cur not in classes:
                classes[cur] = []
                order.append(cur)

print("类总数: %d\n" % len(order))

print("=" * 70)
print("1) 防撤回相关的四个入口在不在")
print("=" * 70)
targets = [
    ("MessageRevokeMgr", "onRevokeMsg:"),
    ("MessageBatchRevokeMgr", "onRevokeMsg:"),
    ("MessageRevokeMgr", "replaceRevokedMsg:"),
    ("MessageRevokeMgr", "batchReplaceRevokedMsg:"),
]
for cls, sel in targets:
    ok = any(s == sel for _, s, _ in classes.get(cls, []))
    print("  %-24s -%-28s %s" % (cls, sel, "✅ 存在" if ok else "❌ 缺失"))

print("\n  MessageRevokeMgr 全部含 revoke 的方法：")
for sign, sel, types in classes.get("MessageRevokeMgr", []):
    if "revoke" in sel.lower():
        print("    %s %-52s [%s]" % (sign, sel, types))

print("\n" + "=" * 70)
print("2) 捕获 CMessageMgr 用的方法还在不在")
print("=" * 70)
for sel in ["init", "InitMsgMgr:", "AsyncOnUnReadChange:", "reloadRevokeMsgNode:",
            "AddMsgPattern:", "checkForSecSystemMsg:", "onSecMsg:", "UpdateVideoStatus:"]:
    ok = any(s == sel for _, s, _ in classes.get("CMessageMgr", []))
    print("  CMessageMgr -%-28s %s" % (sel, "✅" if ok else "❌"))

print("\n" + "=" * 70)
print("3) 插入提示用的 API")
print("=" * 70)
for cls, sel in [("CMessageMgr", "AddLocalMsg:MsgWrap:fixTime:NewMsgArriveNotify:"),
                 ("CMessageWrap", "initWithMsgType:")]:
    ok = any(s == sel for _, s, _ in classes.get(cls, []))
    print("  %-16s -%-56s %s" % (cls, sel, "✅" if ok else "❌"))

print("\n" + "=" * 70)
print("4) 底部栏（TabBar）相关类")
print("=" * 70)
hits = [c for c in order if re.search(r"tabbar", c, re.I)]
for c in sorted(hits):
    print("  %s  (%d 个方法)" % (c, len(classes[c])))

print("\n" + "=" * 70)
print("5) 主界面框架相关类")
print("=" * 70)
hits2 = [c for c in order if re.search(r"(mainframe|newmain|rootview|tabcontroller)", c, re.I)]
for c in sorted(hits2)[:40]:
    print("  %s  (%d 个方法)" % (c, len(classes[c])))
