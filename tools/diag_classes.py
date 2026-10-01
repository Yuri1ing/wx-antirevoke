# -*- coding: utf-8 -*-
"""针对性诊断：方法列表解析是否正确、CMessageMgr 到底有哪些方法。"""
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
print("加载缓存 %.1f MB" % (len(data) / 1048576))

blob = Blob(data, "WeChat")
m = load_machos(blob)[0]

addr, size, foff = m.sections[SECT_CLASSLIST]
n = size // 8
print("classlist: addr=0x%x 条目数=%d" % (addr, n))


def read_class(cls_vm):
    bits_vm = m.ptr_vm(cls_vm + 32)
    if not bits_vm:
        return None, None
    ro_vm = bits_vm & ~0x7
    name_vm = m.ptr_vm(ro_vm + 24)
    methods_vm = m.ptr_vm(ro_vm + 32)
    name = m.cstr_vm(name_vm) if name_vm else None
    if not name:
        return None, None
    return name, methods_vm


print("\n--- 检查第一个类的方法列表原始结构 ---")
for i in range(n):
    raw = struct.unpack_from("<Q", data, foff + i * 8)[0]
    cls_vm = m.decode_ptr(raw)
    if not cls_vm or m.vm_to_off(cls_vm) is None:
        continue
    name, methods_vm = read_class(cls_vm)
    if not name:
        continue
    print("类: %s   methods_vm=0x%x" % (name, methods_vm or 0))
    if methods_vm:
        mo = m.vm_to_off(methods_vm)
        print("  methods 文件偏移: %s" % (hex(mo) if mo else None))
        if mo:
            eaf = struct.unpack_from("<I", data, mo)[0]
            cnt = struct.unpack_from("<I", data, mo + 4)[0]
            print("  entsizeAndFlags=0x%08x  (entsize=%d, flags=0x%x)"
                  % (eaf, eaf & 0xFFFF, eaf & 0xFFFF0000))
            print("  count=%d" % cnt)
            for j in range(min(cnt, 8)):
                eo = mo + 8 + j * 24
                sel_raw = struct.unpack_from("<Q", data, eo)[0]
                sel_vm = m.decode_ptr(sel_raw)
                sel = m.cstr_vm(sel_vm) if sel_vm else None
                print("    [%d] sel_raw=0x%016x sel_vm=0x%x -> %r"
                      % (j, sel_raw, sel_vm or 0, sel))
    break

print("\n--- 全量扫描：哪些类的方法名含 revoke ---")
found = []
cls_count = 0
for i in range(n):
    raw = struct.unpack_from("<Q", data, foff + i * 8)[0]
    cls_vm = m.decode_ptr(raw)
    if not cls_vm or m.vm_to_off(cls_vm) is None:
        continue
    name, methods_vm = read_class(cls_vm)
    if not name:
        continue
    cls_count += 1
    if not methods_vm:
        continue
    mo = m.vm_to_off(methods_vm)
    if not mo:
        continue
    eaf = struct.unpack_from("<I", data, mo)[0]
    cnt = struct.unpack_from("<I", data, mo + 4)[0]
    entsize = eaf & 0xFFFF
    if entsize == 12:
        stride = 12
    elif entsize >= 24:
        stride = 24
    else:
        stride = 24
    if cnt > 100000:
        continue
    for j in range(cnt):
        eo = mo + 8 + j * stride
        if eo + stride > len(data):
            break
        if stride == 24:
            sel_vm = m.decode_ptr(struct.unpack_from("<Q", data, eo)[0])
        else:
            rel = struct.unpack_from("<i", data, eo)[0]
            eo_vm = m.off_to_vm(eo)
            sel_vm = (eo_vm + rel) & 0xFFFFFFFFF if eo_vm else 0
        sel = m.cstr_vm(sel_vm) if sel_vm else None
        if sel and ("revoke" in sel.lower() or "recall" in sel.lower()):
            found.append((name, sel))

print("成功解析的类数: %d" % cls_count)
print("含 revoke/recall 的方法: %d 条" % len(found))
for cls_name, sel in found[:60]:
    print("  %-45s -%s" % (cls_name, sel))
