# -*- coding: utf-8 -*-
"""
用「段归属」作为判据，定位 relative method list 的正确解析方式。

比「字符串看起来像不像 selector」强得多的判据：
  - name  必须落在 __objc_methname 段内
  - types 必须落在 __objc_methtype 段内
只有基准正确时，落点才会 100% 落在对应段里。
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
    if not info:
        return (0, 0)
    a, s, _ = info
    return (a, a + s)


METHNAME = sec_range(b"__objc_methname")
METHTYPE = sec_range(b"__objc_methtype")
CLASSNAME = sec_range(b"__objc_classname")
print("__objc_methname : [0x%x, 0x%x)" % METHNAME)
print("__objc_methtype : [0x%x, 0x%x)" % METHTYPE)
print("__objc_classname: [0x%x, 0x%x)" % CLASSNAME)

addr, size, foff = m.sections[SECT_CLASSLIST]
n = size // 8


def read_class(cls_vm):
    bits_vm = m.ptr_vm(cls_vm + 32)
    if not bits_vm:
        return None, None
    ro_vm = bits_vm & ~0x7
    name_vm = m.ptr_vm(ro_vm + 24)
    methods_vm = m.ptr_vm(ro_vm + 32)
    name = m.cstr_vm(name_vm) if name_vm else None
    return (name, methods_vm) if name else (None, None)


# 收集一批「12 字节相对方法列表」的样本
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
    if (eaf & 0xFFFF) == 12 and 5 <= cnt <= 200:
        samples.append((cname, mvm, mo, cnt))
    if len(samples) >= 300:
        break

print("\n样本方法列表: %d 个" % len(samples))


def in_range(v, r):
    return r[0] <= v < r[1]


def score(field, base_kind, stride, elem_start):
    """统计 field 解出的地址落在 methname / methtype 段内的比例"""
    n_name = n_type = n_total = n_other = 0
    for cname, mvm, mo, cnt in samples:
        for j in range(cnt):
            eo = mo + elem_start + j * stride
            if eo + 12 > len(data):
                break
            rel = struct.unpack_from("<i", data, eo + field)[0]
            eo_vm = m.off_to_vm(eo)
            if eo_vm is None:
                continue
            if base_kind == "self":
                base = eo_vm
            elif base_kind == "self_plus":
                base = eo_vm + field
            elif base_kind == "list":
                base = m.off_to_vm(mo)
            elif base_kind == "image":
                base = m.image_base
            else:
                base = 0
            sv = (base + rel) & 0xFFFFFFFFFFFF
            n_total += 1
            if in_range(sv, METHNAME):
                n_name += 1
            elif in_range(sv, METHTYPE):
                n_type += 1
            else:
                n_other += 1
    return n_name, n_type, n_total, n_other


print("\n%-3s %-5s %-16s | %-22s | %-22s" %
      ("fld", "base", "elem_start", "落在 methname 段", "落在 methtype 段"))
print("-" * 80)
rows = []
for elem_start in (8, 12):
    for field in (0, 4, 8):
        for base_kind in ("self", "self_plus", "list", "image", "zero"):
            nn, nt, tot, no = score(field, base_kind, 12, elem_start)
            rows.append((nn, nt, tot, no, field, base_kind, elem_start))

rows.sort(reverse=True, key=lambda r: max(r[0], r[1]))
for nn, nt, tot, no, field, base_kind, elem_start in rows[:12]:
    print("  %-3d %-5s start=%-6d    | name %5d/%d (%5.1f%%)  | type %5d/%d (%5.1f%%)"
          % (field, base_kind, elem_start, nn, tot, 100.0 * nn / tot,
             nt, tot, 100.0 * nt / tot))

# 用最优组合 dump 一个真实类，人工确认
best = rows[0]
nn, nt, tot, no, field, base_kind, elem_start = best
print("\n=== 用最优组合解析样本（谁是 name 谁是 type 一眼可辨）===")
print("field=%d base=%s elem_start=%d" % (field, base_kind, elem_start))
cname, mvm, mo, cnt = samples[0]
print("类: %s  (%d 个方法)" % (cname, cnt))
for j in range(min(cnt, 20)):
    eo = mo + elem_start + j * 12
    rels = [struct.unpack_from("<i", data, eo + f)[0] for f in (0, 4, 8)]
    eo_vm = m.off_to_vm(eo)
    base = {"self": eo_vm, "self_plus": eo_vm, "list": m.off_to_vm(mo),
            "image": m.image_base, "zero": 0}[base_kind]
    out = []
    for f in (0, 4, 8):
        sv = (base + rels[f]) & 0xFFFFFFFFFFFF
        tag = "NAME" if in_range(sv, METHNAME) else (
            "TYPE" if in_range(sv, METHTYPE) else "----")
        out.append("%s=%r" % (tag, m.cstr_vm(sv)))
    print("  [%2d] %s" % (j, "  ".join(out)))
