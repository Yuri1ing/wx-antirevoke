# -*- coding: utf-8 -*-
"""
反推 name 字段的正确基准。

已知：method_t = 3 个 int32（stride=12），field=4 是 types（基准 = 字段自身地址）。
未知：name 字段（应为 field 0 或 8）的基准。

方法：对每个样本方法 j，假设
    sel_vm = eo_vm + CONST + rel_j
若要求 sel_vm 落在 __objc_methname 段内，则 CONST 必须落在一个区间里。
把所有 j 的区间求交集，交集就是 CONST 的真值（通常是个很小的数）。
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from analyze_wechat import Blob, load_machos, SECT_CLASSLIST

CACHE = r"C:\Users\陈炜坤\Desktop\wx-antirevoke\ipa\微信_8.0.75.macho"
with open(CACHE, "rb") as f:
    data = f.read()
m = load_machos(Blob(data, "WeChat"))[0]


def sec_range(name):
    info = m.sections.get(name)
    return (info[0], info[0] + info[1]) if info else (0, 0)


METHNAME = sec_range(b"__objc_methname")
METHTYPE = sec_range(b"__objc_methtype")
addr, size, foff = m.sections[SECT_CLASSLIST]
n = size // 8

# 收集样本
samples = []
for i in range(n):
    raw = struct.unpack_from("<Q", data, foff + i * 8)[0]
    cls_vm = m.decode_ptr(raw)
    if not cls_vm or m.vm_to_off(cls_vm) is None:
        continue
    bits_vm = m.ptr_vm(cls_vm + 32)
    if not bits_vm:
        continue
    ro_vm = bits_vm & ~0x7
    mvm = m.ptr_vm(ro_vm + 32)
    if not mvm:
        continue
    mo = m.vm_to_off(mvm)
    if not mo:
        continue
    eaf = struct.unpack_from("<I", data, mo)[0]
    cnt = struct.unpack_from("<I", data, mo + 4)[0]
    if (eaf & 0xFFFF) == 12 and 5 <= cnt <= 100:
        samples.append((mo, cnt))
    if len(samples) >= 400:
        break

print("样本: %d 个方法列表" % len(samples))
print("methname: [0x%x, 0x%x)" % METHNAME)
print("methtype: [0x%x, 0x%x)" % METHTYPE)

print("\n=== 先确认 field=4 是 types ===")
lo, hi = None, None
for mo, cnt in samples[:50]:
    for j in range(cnt):
        eo = mo + 8 + j * 12
        eo_vm = m.off_to_vm(eo)
        if eo_vm is None:
            continue
        rel = struct.unpack_from("<i", data, eo + 4)[0]
        a = METHTYPE[0] - eo_vm - rel
        b = METHTYPE[1] - eo_vm - rel
        lo = a if lo is None else max(lo, a)
        hi = b if hi is None else min(hi, b)
print("  CONST 交集: [%s, %s]  ->  %s"
      % (lo, hi, "无解" if (lo is None or lo > hi) else "有效"))

print("\n=== 反推 name 字段 ===")
for field in (0, 4, 8):
    for target_name, target in (("methname", METHNAME),
                                ("methtype", METHTYPE)):
        lo, hi = None, None
        ok = 0
        for mo, cnt in samples[:50]:
            for j in range(cnt):
                eo = mo + 8 + j * 12
                eo_vm = m.off_to_vm(eo)
                if eo_vm is None:
                    continue
                rel = struct.unpack_from("<i", data, eo + field)[0]
                a = target[0] - eo_vm - rel
                b = target[1] - eo_vm - rel
                lo = a if lo is None else max(lo, a)
                hi = b if hi is None else min(hi, b)
                ok += 1
        verdict = "无解"
        if lo is not None and lo <= hi:
            verdict = "✅ CONST ∈ [%d, %d]" % (lo, hi)
        print("  field=%d 目标=%-9s  %s" % (field, target_name, verdict))

print("\n=== 原始字节（第一个样本前 4 个 method_t）===")
mo, cnt = samples[0]
for j in range(min(cnt, 4)):
    eo = mo + 8 + j * 12
    vals = struct.unpack_from("<iii", data, eo)
    uvals = struct.unpack_from("<III", data, eo)
    eo_vm = m.off_to_vm(eo)
    print("  [%d] eo_vm=0x%x" % (j, eo_vm))
    print("      signed  : %d %d %d" % vals)
    print("      unsigned: 0x%08x 0x%08x 0x%08x" % uvals)
    for f in (0, 4, 8):
        rel = vals[f]
        for base_label, base in (("self", eo_vm), ("self+f", eo_vm + f),
                                 ("list", m.off_to_vm(mo))):
            sv = (base + rel) & 0xFFFFFFFFFFFF
            tag = ""
            if METHNAME[0] <= sv < METHNAME[1]:
                tag = "  <<< METHNAME"
            elif METHTYPE[0] <= sv < METHTYPE[1]:
                tag = "  <<< METHTYPE"
            print("      f=%d base=%-7s -> 0x%012x %r%s"
                  % (f, base_label, sv, m.cstr_vm(sv), tag))
