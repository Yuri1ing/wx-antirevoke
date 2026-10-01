# -*- coding: utf-8 -*-
"""诊断 Mach-O / ObjC 解析：段布局、classlist 原始值、指针解码结果。"""
import struct
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from analyze_wechat import (Blob, load_machos, extract_from_ipa, MachO,
                            SECT_CLASSLIST, SECT_CLASSNAME, SECT_METHNAME)

IPA = sys.argv[1] if len(sys.argv) > 1 else \
    r"C:\Users\陈炜坤\Desktop\wx-antirevoke\ipa\微信_8.0.75.ipa"

print("读取 IPA ...")
data, exe, app = extract_from_ipa(IPA)
print("exe=%s app=%s size=%.1fMB" % (exe, app, len(data) / 1048576))

blob = Blob(data, "WeChat")
machos = load_machos(blob)
print("Mach-O 数量: %d" % len(machos))
m = machos[0]

print("\n--- 基本信息 ---")
print("is64            : %s" % m.is64)
print("endian          : %s" % m.endian)
print("cputype         : 0x%x  cpusubtype: 0x%x" % (m.cputype, m.cpusubtype))
print("chained_fixups  : %s" % m.chained_fixups)
print("image_base      : 0x%x" % m.image_base)
print("encrypted       : %s" % m.encrypted)

print("\n--- 段 ---")
for seg in m.segments:
    print("  %-14s vm=0x%012x off=0x%-10x filesize=0x%-10x vmsize=0x%x"
          % (seg.name, seg.vmaddr, seg.fileoff, seg.filesize, seg.vmsize))
    for sname, (saddr, ssize, sfoff) in seg.sections.items():
        if sname in (SECT_CLASSLIST, SECT_CLASSNAME, SECT_METHNAME):
            print("      %-22s addr=0x%012x size=0x%-8x off=0x%x"
                  % (sname.decode(), saddr, ssize, sfoff))

print("\n--- __objc_classlist 原始值 ---")
info = m.sections.get(SECT_CLASSLIST)
if not info:
    print("  未找到 __objc_classlist")
    sys.exit(1)
addr, size, foff = info
print("  addr=0x%x size=0x%x off=0x%x  条目数=%d" % (addr, size, foff, size // 8))
print("  vm_to_off(addr) = %s" % m.vm_to_off(addr))

for i in range(8):
    off = foff + i * 8
    raw = struct.unpack_from("<Q", m.blob.data, off)[0]
    dec = m.decode_ptr(raw)
    offdec = m.vm_to_off(dec) if dec else None
    print("  [%d] raw=0x%016x  target=0x%09x  decoded=0x%012x  vm_to_off=%s"
          % (i, raw, raw & 0xFFFFFFFFF, dec, hex(offdec) if offdec else None))

print("\n--- 取第一个解码成功的类，手动走一遍结构 ---")
cls_vm = None
for i in range(size // 8):
    raw = struct.unpack_from("<Q", m.blob.data, foff + i * 8)[0]
    d = m.decode_ptr(raw)
    if d and m.vm_to_off(d) is not None:
        cls_vm = d
        print("  第 %d 项解码成功: 0x%x" % (i, cls_vm))
        break
if cls_vm is None:
    print("  没有任何一项解码后落在有效段内 —— 说明 decode_ptr 的语义假设不对")
    sys.exit(2)

print("\n  --- objc_class 结构 ---")
for name, o in (("isa", 0), ("superclass", 8), ("cache.buckets", 16),
                ("cache.mask+occupied", 24), ("bits(data)", 32)):
    off = m.vm_to_off(cls_vm + o)
    raw = struct.unpack_from("<Q", m.blob.data, off)[0] if off is not None else None
    dec = m.decode_ptr(raw) if raw is not None else None
    print("  +%-3d %-20s raw=0x%016x decoded=0x%x"
          % (o, name, raw if raw is not None else 0, dec or 0))

bits_off = m.vm_to_off(cls_vm + 32)
bits = struct.unpack_from("<Q", m.blob.data, bits_off)[0]
bits_dec = m.decode_ptr(bits)
ro_vm = bits_dec & ~0x7
print("  bits_dec=0x%x  ro_vm=0x%x  ro→off=%s"
      % (bits_dec, ro_vm, m.vm_to_off(ro_vm)))

if m.vm_to_off(ro_vm) is not None:
    ro_off = m.vm_to_off(ro_vm)
    print("\n  --- class_ro_t ---")
    for name, o, sz in (("flags", 0, 4), ("instanceStart", 4, 4),
                        ("instanceSize", 8, 4), ("reserved", 12, 4),
                        ("ivarLayout", 16, 8), ("name", 24, 8),
                        ("baseMethods", 32, 8)):
        if sz == 4:
            v = struct.unpack_from("<I", m.blob.data, ro_off + o)[0]
            print("  +%-3d %-16s = 0x%x (%d)" % (o, name, v, v))
        else:
            raw = struct.unpack_from("<Q", m.blob.data, ro_off + o)[0]
            dec = m.decode_ptr(raw)
            extra = ""
            if name == "name" and dec and m.vm_to_off(dec) is not None:
                s = m.cstr_vm(dec)
                extra = "  -> \"%s\"" % s
            if name == "baseMethods" and dec:
                extra = "  off=%s" % m.vm_to_off(dec)
            print("  +%-3d %-16s raw=0x%016x dec=0x%012x%s"
                  % (o, name, raw, dec, extra))

print("\n完成")
