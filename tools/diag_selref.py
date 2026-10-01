# -*- coding: utf-8 -*-
"""
验证假设：relative method_t 的 name 字段指向 __objc_selrefs 中的一个 SEL 指针，
需要再解引用一次才能拿到 __objc_methname 里的字符串。
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
SELREFS = sec_range(b"__objc_selrefs")
CLASSLIST = sec_range(b"__objc_classlist")
print("methname : [0x%x, 0x%x)" % METHNAME)
print("methtype : [0x%x, 0x%x)" % METHTYPE)
print("selrefs  : [0x%x, 0x%x)" % SELREFS)
print("classlist: [0x%x, 0x%x)" % CLASSLIST)

addr, size, foff = m.sections[SECT_CLASSLIST]
n = size // 8


def read_class(cls_vm):
    bits_vm = m.ptr_vm(cls_vm + 32)
    if not bits_vm:
        return None, None
    ro_vm = bits_vm & ~0x7
    name_vm = m.ptr_vm(ro_vm + 24)
    methods_vm = m.ptr_vm(ro_vm + 32)
    nm = m.cstr_vm(name_vm) if name_vm else None
    return (nm, methods_vm) if nm else (None, None)


samples = []
for i in range(n):
    raw = struct.unpack_from("<Q", data, foff + i * 8)[0]
    cls_vm = m.decode_ptr(raw)
    if not cls_vm or m.vm_to_off(cls_vm) is None:
        continue
    cname, mvm = read_class(cls_vm)
    if not cname or not mvm:
        continue
    mo = m.vm_to_off(mvm)
    if not mo:
        continue
    eaf = struct.unpack_from("<I", data, mo)[0]
    cnt = struct.unpack_from("<I", data, mo + 4)[0]
    if (eaf & 0xFFFF) == 12 and 3 <= cnt <= 100:
        samples.append((cname, mo, cnt))
    if len(samples) >= 500:
        break

print("\n样本: %d 个方法列表" % len(samples))

# --- 统计 field=0 落点分布 ---
buckets = {"methname": 0, "methtype": 0, "selrefs": 0, "other": 0}
total = 0
for cname, mo, cnt in samples:
    for j in range(cnt):
        eo = mo + 8 + j * 12
        eo_vm = m.off_to_vm(eo)
        if eo_vm is None:
            continue
        rel = struct.unpack_from("<i", data, eo)[0]
        sv = (eo_vm + rel) & 0xFFFFFFFFFFFF
        total += 1
        if METHNAME[0] <= sv < METHNAME[1]:
            buckets["methname"] += 1
        elif METHTYPE[0] <= sv < METHTYPE[1]:
            buckets["methtype"] += 1
        elif SELREFS[0] <= sv < SELREFS[1]:
            buckets["selrefs"] += 1
        else:
            buckets["other"] += 1

print("\nfield=0 以「method_t 自身地址」为基准的落点分布 (共 %d):" % total)
for k, v in buckets.items():
    print("  %-10s %6d  (%5.1f%%)" % (k, v, 100.0 * v / total))

# --- 测试二次解引用 ---
print("\n=== 测试：先取 SEL* ，再解引用 ===")
ok1 = ok2 = 0
tested = 0
shown = 0
for cname, mo, cnt in samples:
    for j in range(cnt):
        eo = mo + 8 + j * 12
        eo_vm = m.off_to_vm(eo)
        if eo_vm is None:
            continue
        rel = struct.unpack_from("<i", data, eo)[0]
        ptr_vm = (eo_vm + rel) & 0xFFFFFFFFFFFF
        tested += 1
        # 一次解引用
        inner = m.ptr_vm(ptr_vm)
        if inner and METHNAME[0] <= inner < METHNAME[1]:
            ok1 += 1
            if shown < 8:
                print("  [1 次] %s  -%s" % (cname, m.cstr_vm(inner)))
                shown += 1
        # 直接当字符串
        elif METHNAME[0] <= ptr_vm < METHNAME[1]:
            ok2 += 1

print("\n  样本总数: %d" % tested)
print("  一次解引用后落在 methname 段: %d (%.1f%%)" % (ok1, 100.0 * ok1 / tested))
print("  本身就是 methname 地址        : %d (%.1f%%)" % (ok2, 100.0 * ok2 / tested))

# --- 看看真实内容 ---
print("\n=== 原始观测（第一个样本前 3 个方法）===")
cname, mo, cnt = samples[0]
print("类: %s" % cname)
for j in range(min(cnt, 3)):
    eo = mo + 8 + j * 12
    eo_vm = m.off_to_vm(eo)
    vals = list(struct.unpack_from("<iii", data, eo))
    print("  [%d] eo_vm=0x%x  字段=%s" % (j, eo_vm, vals))
    for f in (0, 4, 8):
        rel = vals[f]
        sv = (eo_vm + rel) & 0xFFFFFFFFFFFF
        line = "      f=%d rel=%-12d sv=0x%012x" % (f, rel, sv)
        if METHNAME[0] <= sv < METHNAME[1]:
            line += "  methname -> %r" % m.cstr_vm(sv)
        elif METHTYPE[0] <= sv < METHTYPE[1]:
            line += "  methtype -> %r" % m.cstr_vm(sv)
        elif SELREFS[0] <= sv < SELREFS[1]:
            inner = m.ptr_vm(sv)
            line += "  selrefs -> (*)=0x%x %r" % (
                inner or 0, m.cstr_vm(inner) if inner else None)
        else:
            line += "  -> %r" % m.cstr_vm(sv)
        print(line)
