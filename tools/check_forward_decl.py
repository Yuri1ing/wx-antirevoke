# -*- coding: utf-8 -*-
"""
检查 C 源码里「函数在定义之前被调用」的问题。

C 语言要求函数先声明/定义后使用，否则是硬错误（implicit declaration）。
Theos/clang 下表现为编译失败。这个脚本把这类问题一次性找出来。
"""
import re
import sys
import os

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

path = sys.argv[1] if len(sys.argv) > 1 else r"tweak\AntiRevoke.m"
with open(path, encoding="utf-8") as f:
    lines = f.readlines()

# 1) 找出所有 static 函数定义： static <ret...> name(...)  {  或  ... \n{
#    形如： static BOOL WXARFoo(Class cls, ...) {
def_re = re.compile(
    r'^\s*static\s+[\w\s\*<>,\[\]]+?[\s\*](\w+)\s*\([^;]*$')
alt_re = re.compile(
    r'^\s*static\s+[\w\s\*<>,\[\]]+?[\s\*](\w+)\s*\([^;]*\)\s*\{')

defs = {}      # name -> line number (1-based)
for i, line in enumerate(lines, 1):
    if line.lstrip().startswith('//') or line.lstrip().startswith('///'):
        continue
    m = alt_re.match(line)
    if m:
        defs.setdefault(m.group(1), i)
        continue
    m = def_re.match(line)
    if m:
        # 多行签名：下一行可能是 { 或者继续参数
        defs.setdefault(m.group(1), i)

# 2) 前置声明（以 ; 结尾的 static 函数声明）
forward = {}
for i, line in enumerate(lines, 1):
    if re.match(r'^\s*static\s+[\w\s\*<>,\[\]]+?[\s\*](\w+)\s*\([^)]*\)\s*;\s*$', line):
        nm = re.match(r'^\s*static\s+[\w\s\*<>,\[\]]+?[\s\*](\w+)\s*\(', line)
        if nm:
            forward.setdefault(nm.group(1), i)

print("发现 static 函数定义 %d 个，前置声明 %d 个\n" % (len(defs), len(forward)))

# 3) 对每个函数，找所有「调用」位置，看是否有早于定义（且早于前置声明）的
problems = []
for name, dline in sorted(defs.items(), key=lambda kv: kv[1]):
    fline = forward.get(name)
    earliest_ok = dline
    if fline and fline < dline:
        earliest_ok = fline

    # 收集调用点（不是定义行本身、不是注释行）
    call_re = re.compile(r'\b' + re.escape(name) + r'\s*\(')
    for i, line in enumerate(lines, 1):
        if i == dline or i == fline:
            continue
        stripped = line.lstrip()
        if stripped.startswith('//') or stripped.startswith('///') or stripped.startswith('*'):
            continue
        if not call_re.search(line):
            continue
        # 定义行本身可能被误判（多行签名），已经跳过
        if i < earliest_ok:
            problems.append((name, i, dline, fline))

if not problems:
    print("✅ 没有发现「先用后定义」的问题")
else:
    print("❌ 发现 %d 处「调用早于定义」：" % len(problems))
    for name, call_line, def_line, fwd in problems:
        fwd_s = ("，前置声明在第 %d 行" % fwd) if fwd else "，且无前置声明"
        print("  %s：第 %d 行调用，但定义在第 %d 行%s"
              % (name, call_line, def_line, fwd_s))
