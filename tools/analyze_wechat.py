#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
analyze_wechat.py — 离线解析 iOS 微信 Mach-O，定位「撤回消息」相关的
Objective-C 类与方法，为 Theos 防撤回插件提供精确 hook 点。

用法:
    python analyze_wechat.py <ipa文件或Mach-O路径>
    python analyze_wechat.py wechat.ipa --dump-classes classes.txt
    python analyze_wechat.py wechat.ipa --keyword revoke --keyword recall

设计要点:
    - 纯标准库，Windows / macOS / Linux 通用，无需安装任何东西
    - 支持 fat (universal) 与 thin Mach-O
    - 解析 __objc_classlist -> class_t -> class_ro_t -> method_list_t
    - 同时兼容「绝对指针方法列表」(entsize=24) 与「相对偏移方法列表」(entsize=12)
    - 掩掉 PAC 高位，避免 arm64e 上指针解析失败
    - 每一步都做边界检查，坏数据不会导致崩溃，只会记录警告
"""

import argparse
import io
import mmap
import os
import plistlib
import re
import struct
import sys
import zipfile

# Windows 控制台默认 GBK，强制用 UTF-8 输出，避免中文乱码
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass

# ---------------------------------------------------------------- Mach-O 常量

MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

LC_SEGMENT = 0x01
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_DYLD_EXPORTS_TRIE = 0x80000033

# ObjC 段名
SECT_CLASSLIST = b"__objc_classlist"
SECT_CATLIST = b"__objc_catlist"
SECT_CLASSNAME = b"__objc_classname"
SECT_METHNAME = b"__objc_methname"
SECT_CSTRING = b"__cstring"

# arm64e PAC 掩码：iOS 用户态地址空间远小于 2^47
PTR_MASK = 0x0000FFFFFFFFFFFF

# 我们关心的关键词：撤回 + 周边逻辑
DEFAULT_KEYWORDS = [
    "revoke", "Revoke", "recall", "Recall", "withdraw", "Withdraw",
    "undo", "Undo", "撤回",
]

# 值得关注的类名前缀（微信消息/会话核心类）
CLASS_INTEREST = re.compile(
    r"(Message|Msg|Session|Chat|Logic|Contact|Revoke|Recall)", re.IGNORECASE
)


def warn(msg):
    print("  [warn] " + msg, file=sys.stderr)


# ---------------------------------------------------------------- 基础读取器

class Blob:
    """一段可随机访问的二进制数据（文件或 mmap）。"""

    def __init__(self, data, name="<blob>", base=0):
        self.data = data
        self.name = name
        self.base = base  # 该 blob 在容器中的起始偏移

    def __len__(self):
        return len(self.data)

    def read(self, off, size):
        if off < 0 or size < 0 or off + size > len(self.data):
            return None
        return self.data[off:off + size]

    def u8(self, off):
        b = self.read(off, 1)
        return b[0] if b else None

    def u16(self, off, endian="<"):
        b = self.read(off, 2)
        return struct.unpack(endian + "H", b)[0] if b else None

    def u32(self, off, endian="<"):
        b = self.read(off, 4)
        return struct.unpack(endian + "I", b)[0] if b else None

    def u64(self, off, endian="<"):
        b = self.read(off, 8)
        return struct.unpack(endian + "Q", b)[0] if b else None

    def cstr(self, off, limit=4096):
        if off < 0 or off >= len(self.data):
            return None
        end = self.data.find(b"\x00", off, min(off + limit, len(self.data)))
        if end < 0:
            end = min(off + limit, len(self.data))
        raw = self.data[off:end]
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return raw.decode("latin-1")
            except Exception:
                return None


# ---------------------------------------------------------------- Mach-O 解析

class Segment:
    __slots__ = ("name", "vmaddr", "vmsize", "fileoff", "filesize", "sections")

    def __init__(self, name, vmaddr, vmsize, fileoff, filesize):
        self.name = name
        self.vmaddr = vmaddr
        self.vmsize = vmsize
        self.fileoff = fileoff
        self.filesize = filesize
        self.sections = {}  # sectname -> (addr, size, offset)

    def __repr__(self):
        return "Segment(%s vm=0x%x off=0x%x size=0x%x)" % (
            self.name, self.vmaddr, self.fileoff, self.filesize)


class MachO:
    """单个架构的 Mach-O 文件解析器。"""

    def __init__(self, blob, label="macho"):
        self.blob = blob
        self.label = label
        self.endian = "<"
        self.is64 = False
        self.cputype = 0
        self.cpusubtype = 0
        self.segments = []
        self.sections = {}       # sectname -> (vmaddr, size, fileoff)
        self.encrypted = False
        self.cryptoff = 0
        self.cryptsize = 0
        # 现代 iOS 二进制用 chained fixups 编码指针，不能直接当虚拟地址读
        self.chained_fixups = False
        self.image_base = 0
        self._parse()

    # -- 段/虚拟地址工具 ------------------------------------------------

    def vm_to_off(self, vmaddr):
        """把虚拟地址转换成文件偏移。跳过 __PAGEZERO 这类无文件内容的段。"""
        for seg in self.segments:
            if seg.filesize == 0:
                continue
            if seg.vmaddr <= vmaddr < seg.vmaddr + seg.vmsize:
                off = seg.fileoff + (vmaddr - seg.vmaddr)
                if 0 <= off < len(self.blob):
                    return off
                return None
        return None

    def decode_ptr(self, raw):
        """
        解码一个 64 位指针。

        新版 iOS 二进制（LC_DYLD_CHAINED_FIXUPS）里，__DATA_CONST 中的指针
        被编码成 rebase/bind 信息，直接当地址读会拿到垃圾。
        这里按 DYLD_CHAINED_PTR_64 / DYLD_CHAINED_PTR_64_OFFSET 解出 target，
        再用「解出来的地址是否落在某个真实段内」来判定到底是偏移语义还是绝对语义。
        """
        if raw is None or raw == 0:
            return 0
        if not self.chained_fixups:
            return raw & PTR_MASK
        if (raw >> 63) & 1:
            return 0                      # bind：指向外部符号，不是我们要的
        target = raw & 0xFFFFFFFFF        # 36 位 target
        as_offset = self.image_base + target
        if self.vm_to_off(as_offset) is not None:
            return as_offset
        if self.vm_to_off(target) is not None:
            return target
        return as_offset                  # 兜底，交给调用方判空

    def ptr_at(self, off):
        """按文件偏移读一个指针并解码。"""
        return self.decode_ptr(self.blob.u64(off, self.endian))

    def ptr_vm(self, vmaddr):
        """按虚拟地址读一个指针并解码（vmaddr 是「指针存放的位置」）。"""
        off = self.vm_to_off(vmaddr)
        if off is None:
            return None
        return self.ptr_at(off)

    def off_to_vm(self, off):
        """把文件偏移转换成虚拟地址（相对方法列表需要这个基准）。"""
        for seg in self.segments:
            if seg.fileoff <= off < seg.fileoff + seg.filesize:
                return seg.vmaddr + (off - seg.fileoff)
        return None

    def read_vm(self, vmaddr, size):
        off = self.vm_to_off(vmaddr)
        if off is None:
            return None
        return self.blob.read(off, size)

    def u32_vm(self, vmaddr):
        off = self.vm_to_off(vmaddr)
        return self.blob.u32(off, self.endian) if off is not None else None

    def u64_vm(self, vmaddr):
        off = self.vm_to_off(vmaddr)
        return self.blob.u64(off, self.endian) if off is not None else None

    def cstr_vm(self, vmaddr):
        off = self.vm_to_off(vmaddr)
        return self.blob.cstr(off) if off is not None else None

    def ptr_size(self):
        return 8 if self.is64 else 4

    # -- 头部解析 --------------------------------------------------------

    def _parse(self):
        magic = self.blob.u32(0, "<")
        if magic in (MH_MAGIC_64,):
            self.endian, self.is64 = "<", True
        elif magic in (MH_CIGAM_64,):
            self.endian, self.is64 = ">", True
        elif magic in (MH_MAGIC,):
            self.endian, self.is64 = "<", False
        elif magic in (MH_CIGAM,):
            self.endian, self.is64 = ">", False
        else:
            raise ValueError("不是有效的 Mach-O (magic=0x%08x)" % (magic or 0))

        e = self.endian
        self.cputype = self.blob.u32(4, e)
        self.cpusubtype = self.blob.u32(8, e)
        ncmds = self.blob.u32(16, e)
        if self.is64:
            sizeofcmds = self.blob.u32(20, e)
            off = 32
        else:
            sizeofcmds = self.blob.u32(20, e)
            off = 28

        if ncmds is None or ncmds > 100000:
            raise ValueError("ncmds 异常: %r" % ncmds)

        for _ in range(ncmds):
            cmd = self.blob.u32(off, e)
            cmdsize = self.blob.u32(off + 4, e)
            if cmd is None or cmdsize is None or cmdsize < 8:
                break
            if cmd == LC_SEGMENT_64 and self.is64:
                self._parse_segment64(off)
            elif cmd == LC_SEGMENT and not self.is64:
                self._parse_segment32(off)
            elif cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
                self.cryptoff = self.blob.u32(off + 8, e)
                self.cryptsize = self.blob.u32(off + 12, e)
                cryptid = self.blob.u32(off + 16, e)
                self.encrypted = bool(cryptid)
            elif cmd == LC_DYLD_CHAINED_FIXUPS:
                self.chained_fixups = True
            off += cmdsize

        # image base：第一个有实际内容的段的 vmaddr（跳过 __PAGEZERO）
        for seg in self.segments:
            if seg.name != "__PAGEZERO" and seg.filesize > 0:
                self.image_base = seg.vmaddr
                break

        # 建立 sectname -> 信息 的索引（同名段优先 __TEXT/__DATA）
        for seg in self.segments:
            for sname, info in seg.sections.items():
                if sname not in self.sections:
                    self.sections[sname] = info

    def _parse_segment64(self, off):
        e = self.endian
        segname = (self.blob.read(off + 8, 16) or b"").split(b"\x00")[0].decode(
            "latin-1", "replace")
        vmaddr = self.blob.u64(off + 24, e)
        vmsize = self.blob.u64(off + 32, e)
        fileoff = self.blob.u64(off + 40, e)
        filesize = self.blob.u64(off + 48, e)
        nsects = self.blob.u32(off + 64, e)
        if None in (vmaddr, vmsize, fileoff, filesize, nsects):
            return
        seg = Segment(segname, vmaddr, vmsize, fileoff, filesize)
        soff = off + 72
        for _ in range(min(nsects, 4096)):
            sname = (self.blob.read(soff, 16) or b"").split(b"\x00")[0]
            saddr = self.blob.u64(soff + 32, e)
            ssize = self.blob.u64(soff + 40, e)
            sfoff = self.blob.u32(soff + 48, e)
            if saddr is not None and ssize is not None and sfoff is not None:
                seg.sections[sname] = (saddr, ssize, sfoff)
            soff += 80
        self.segments.append(seg)

    def _parse_segment32(self, off):
        e = self.endian
        segname = (self.blob.read(off + 8, 16) or b"").split(b"\x00")[0].decode(
            "latin-1", "replace")
        vmaddr = self.blob.u32(off + 24, e)
        vmsize = self.blob.u32(off + 28, e)
        fileoff = self.blob.u32(off + 32, e)
        filesize = self.blob.u32(off + 36, e)
        nsects = self.blob.u32(off + 48, e)
        if None in (vmaddr, vmsize, fileoff, filesize, nsects):
            return
        seg = Segment(segname, vmaddr, vmsize, fileoff, filesize)
        soff = off + 56
        for _ in range(min(nsects, 4096)):
            sname = (self.blob.read(soff, 16) or b"").split(b"\x00")[0]
            saddr = self.blob.u32(soff + 32, e)
            ssize = self.blob.u32(soff + 36, e)
            sfoff = self.blob.u32(soff + 40, e)
            if saddr is not None and ssize is not None and sfoff is not None:
                seg.sections[sname] = (saddr, ssize, sfoff)
            soff += 68
        self.segments.append(seg)

    # -- ObjC 元数据 -----------------------------------------------------

    def section_data(self, sname):
        info = self.sections.get(sname)
        if not info:
            return None, 0, 0
        addr, size, foff = info
        return self.blob.read(foff, size), addr, size

    def class_list(self):
        """返回 [(className, [(selName, typeEncoding), ...]), ...]"""
        data, addr, size = self.section_data(SECT_CLASSLIST)
        if not data:
            return []
        ps = self.ptr_size()
        out = []
        n = size // ps
        for i in range(n):
            if self.is64:
                raw = struct.unpack_from(self.endian + "Q", data, i * 8)[0]
            else:
                raw = struct.unpack_from(self.endian + "I", data, i * 4)[0]
            cls_vm = self.decode_ptr(raw)
            if not cls_vm:
                continue
            try:
                info = self._read_class(cls_vm)
            except Exception as exc:  # noqa: BLE001
                continue
            if info:
                out.append(info)
        return out

    def _read_class(self, cls_vm):
        ps = self.ptr_size()
        # objc_class 布局（64 位）：
        #   +0  isa              8
        #   +8  superclass       8
        #   +16 cache            16  (buckets 8 + mask/occupied 8)
        #   +32 bits(class_data_bits_t)   <-- 注意是 32，不是 24
        bits_off = 4 * ps
        bits_vm = (self.ptr_vm(cls_vm + bits_off) if self.is64
                   else self.u32_vm(cls_vm + bits_off))
        if not bits_vm:
            return None
        ro_vm = bits_vm & ~0x7
        ro_vm &= PTR_MASK
        if ro_vm == 0:
            return None
        return self._read_class_ro(ro_vm)

    def _i32_at(self, off):
        b = self.blob.read(off, 4)
        return struct.unpack(self.endian + "i", b)[0] if b else None

    def _resolve_sel(self, slot_vm):
        """
        解析 selector 字符串。

        微信这份二进制用的是「间接 selector」编码：relative method_t 的 name
        字段（相对它自己）指向 __objc_selrefs 里的一个槽，要再解引用一次
        才拿到 __objc_methname 里的真字符串。
        但别的 App / 版本可能直接指向 __objc_methname，所以两种都试。
        """
        mn = self.sections.get(SECT_METHNAME)
        if mn:
            lo, hi = mn[0], mn[0] + mn[1]
            if lo <= slot_vm < hi:
                return self.cstr_vm(slot_vm)
        inner = self.ptr_vm(slot_vm)
        if inner:
            s = self.cstr_vm(inner)
            if s and re.match(r"^[A-Za-z_][A-Za-z0-9_:]{0,300}$", s):
                return s
        return None

    def _read_class_ro(self, ro_vm):
        ps = self.ptr_size()
        if self.is64:
            name_vm = self.ptr_vm(ro_vm + 24)
            methods_vm = self.ptr_vm(ro_vm + 32)
        else:
            name_vm = self.u32_vm(ro_vm + 12)
            methods_vm = self.u32_vm(ro_vm + 16)
        if not name_vm:
            return None
        name = self.cstr_vm(name_vm & PTR_MASK)
        if not name:
            return None
        methods = []
        if methods_vm:
            # 读取 method_list_t: entsizeAndFlags(4) count(4) entries...
            mo = self.vm_to_off(methods_vm & PTR_MASK)
            if mo is not None:
                entsize_and_flags = self.blob.u32(mo, self.endian)
                count = self.blob.u32(mo + 4, self.endian)
                if entsize_and_flags is not None and count is not None:
                    entsize = entsize_and_flags & 0xFFFF
                    if entsize > 0x8000:      # 明显不合理，标记位混入
                        entsize = entsize_and_flags & ~0x3
                    relative = bool(entsize_and_flags & 0x80000000) or entsize == 12
                    if relative:
                        stride = 12
                    elif entsize >= (24 if self.is64 else 12):
                        stride = 24 if self.is64 else 12
                    else:
                        stride = 24 if self.is64 else 12
                    if count > 300000:        # 保护：明显越界
                        count = 0
                    base = mo + 8
                    for j in range(count):
                        eo = base + j * stride
                        if eo + stride > len(self.blob):
                            break
                        if relative:
                            eo_vm = self.off_to_vm(eo)
                            if eo_vm is None:
                                continue
                            rel_name = self._i32_at(eo)
                            rel_types = self._i32_at(eo + 4)
                            sel = None
                            if rel_name is not None:
                                sel = self._resolve_sel(
                                    (eo_vm + rel_name) & PTR_MASK)
                            types = None
                            if rel_types is not None:
                                types = self.cstr_vm(
                                    (eo_vm + 4 + rel_types) & PTR_MASK)
                        else:
                            if self.is64:
                                sel_vm = self.ptr_at(eo)
                                types_vm = self.ptr_at(eo + 8)
                            else:
                                sel_vm = self.blob.u32(eo, self.endian)
                                types_vm = self.blob.u32(eo + 4, self.endian)
                            if not sel_vm:
                                continue
                            sel = self.cstr_vm(sel_vm & PTR_MASK)
                            types = (self.cstr_vm(types_vm & PTR_MASK)
                                     if types_vm else None)
                        if sel:
                            methods.append((sel, types or ""))
        return (name, methods)

    def string_section(self, sname):
        """返回某个 cstring 段里的全部字符串。"""
        data, _, _ = self.section_data(sname)
        if not data:
            return []
        return [s.decode("utf-8", "replace")
                for s in data.split(b"\x00") if len(s) >= 3]


# ---------------------------------------------------------------- 容器处理

def sniff_macho(blob):
    m = blob.u32(0, ">")
    if m in (FAT_MAGIC, FAT_MAGIC_64):
        return "fat_be"
    m = blob.u32(0, "<")
    if m in (FAT_MAGIC, FAT_MAGIC_64):
        return "fat_le"
    if m in (MH_MAGIC_64, MH_MAGIC, MH_CIGAM_64, MH_CIGAM):
        return "thin"
    if m in (MH_CIGAM_64, MH_CIGAM):
        return "thin"
    return None


def load_machos(blob):
    """把一个文件拆成一或多个 MachO 对象（处理 fat）。"""
    kind = sniff_macho(blob)
    if kind is None:
        return []
    if kind == "thin":
        return [MachO(blob, "thin")]

    # FAT
    endian = ">" if kind == "fat_be" else "<"
    is64 = blob.u32(0, endian) in (FAT_MAGIC_64,)
    nfat = blob.u32(4, endian)
    if not nfat or nfat > 64:
        return []
    out = []
    entry_size = 32 if is64 else 20
    for i in range(nfat):
        eo = 8 + i * entry_size
        if is64:
            cputype = blob.u32(eo, endian)
            offset = blob.u64(eo + 8, endian)
            size = blob.u64(eo + 16, endian)
        else:
            cputype = blob.u32(eo, endian)
            offset = blob.u32(eo + 8, endian)
            size = blob.u32(eo + 12, endian)
        if offset is None or size is None or size == 0:
            continue
        if offset + size > len(blob):
            continue
        sub = Blob(blob.data[offset:offset + size],
                   "slice%d" % i, base=0)
        try:
            m = MachO(sub, "slice%d(cpu=0x%x)" % (i, cputype or 0))
            out.append(m)
        except Exception as exc:  # noqa: BLE001
            warn("跳过 slice %d: %s" % (i, exc))
    return out


def extract_from_ipa(path):
    """从 .ipa 里取出主二进制的字节。"""
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        payload_apps = sorted({n.split("/")[1] for n in names
                               if n.startswith("Payload/")
                               and len(n.split("/")) > 2})
        if not payload_apps:
            return None, None, None
        app = payload_apps[0]
        prefix = "Payload/%s/" % app

        # 读 Info.plist 找 CFBundleExecutable
        exe_name = None
        for plist_name in ("Info.plist",):
            p = prefix + plist_name
            if p in names:
                try:
                    info = plistlib.loads(zf.read(p))
                    exe_name = info.get("CFBundleExecutable")
                except Exception as exc:  # noqa: BLE001
                    warn("Info.plist 解析失败: %s" % exc)
                break
        if not exe_name:
            # 兜底：找 Payload/Xxx.app/Xxx 这样的条目
            base = app[:-4] if app.endswith(".app") else app
            if prefix + base in names:
                exe_name = base
        if not exe_name:
            return None, None, app

        target = prefix + exe_name
        if target not in names:
            return None, None, app
        data = zf.read(target)
        return data, exe_name, app


# ---------------------------------------------------------------- 分析逻辑

def score_selector(sel, types, classname):
    """给一个 method 打分，分越高越可能是撤回处理入口。"""
    s = 0
    low = sel.lower()
    if "revoke" in low:
        s += 100
    if "recall" in low or "withdraw" in low:
        s += 70
    if "undo" in low:
        s += 25
    # 强候选：方法名直接是 RevokeMsg: / onRevokeMsg:
    if re.fullmatch(r"(on)?revoke(msg|message)?:?", sel, re.IGNORECASE):
        s += 60
    # 撤回处理一般是 1 个参数、返回 void
    argc = types.count(":") if types else sel.count(":")
    if argc == 1:
        s += 10
    if types.startswith("v") or not types:
        s += 8
    if CLASS_INTEREST.search(classname or ""):
        s += 5
    return s


def analyze(machos, keywords, top=60):
    results = []
    seen_names = set()
    total_classes = 0
    for mi, m in enumerate(machos):
        if m.is64:
            arch = "arm64" if m.cputype == 0x0100000C else "cpu=0x%x" % m.cputype
        else:
            arch = "armv7" if m.cputype == 12 else "cpu=0x%x" % m.cputype
        label = "slice%d[%s]" % (mi, arch)
        print("\n=== %s ===" % label)
        print("  段数量: %d, 加密: %s" % (
            len(m.segments),
            "YES cryptoff=0x%x cryptsize=0x%x" % (m.cryptoff, m.cryptsize)
            if m.encrypted else "no"))
        seg_names = ", ".join(s.name for s in m.segments)
        print("  段: %s" % seg_names)
        has_classlist = SECT_CLASSLIST in m.sections
        print("  __objc_classlist: %s" % ("找到" if has_classlist else "缺失"))

        # 1) 类名 / 方法名 段原文
        classnames = m.string_section(SECT_CLASSNAME)
        methnames = m.string_section(SECT_METHNAME)
        print("  __objc_classname 字符串: %d" % len(classnames))
        print("  __objc_methname  字符串: %d" % len(methnames))

        # 2) 完整类 -> 方法映射
        classes = m.class_list()
        print("  解析出类: %d" % len(classes))
        total_classes += len(classes)

        for cname, methods in classes:
            if cname in seen_names:
                continue
            seen_names.add(cname)
            for sel, types in methods:
                sc = score_selector(sel, types, cname)
                if sc > 0:
                    results.append({
                        "score": sc, "class": cname, "selector": sel,
                        "types": types, "slice": label,
                    })

        # 3) 纯字符串兜底：即使 classlist 解析失败，也能看到候选方法名
        if not classes:
            for s in methnames:
                if any(k.lower() in s.lower() for k in keywords):
                    results.append({
                        "score": 40, "class": "?", "selector": s,
                        "types": "", "slice": label,
                    })
        for s in classnames:
            if any(k.lower() in s.lower() for k in keywords):
                results.append({
                    "score": 30, "class": s, "selector": "(类名命中)",
                    "types": "", "slice": label,
                })

    results.sort(key=lambda r: -r["score"])
    return results, total_classes


def main():
    ap = argparse.ArgumentParser(
        description="解析 iOS 微信 Mach-O，定位撤回相关方法")
    ap.add_argument("target", help="IPA 文件或 Mach-O 文件路径")
    ap.add_argument("--keyword", action="append", default=None,
                    help="自定义关键词，可重复")
    ap.add_argument("--top", type=int, default=60, help="输出前 N 条候选")
    ap.add_argument("--dump-classes", default=None,
                    help="把全部类及其方法写到该文件")
    args = ap.parse_args()

    path = args.target
    if not os.path.exists(path):
        print("文件不存在: %s" % path, file=sys.stderr)
        return 2

    keywords = args.keyword or DEFAULT_KEYWORDS

    print("=" * 68)
    print("微信防撤回 · 离线符号分析")
    print("=" * 68)
    print("目标: %s (%.1f MB)" % (path, os.path.getsize(path) / 1048576))

    data = None
    cache_path = os.path.splitext(path)[0] + ".macho"
    if path.lower().endswith(".ipa") or zipfile.is_zipfile(path):
        if os.path.exists(cache_path):
            print("使用已解压缓存: %s" % cache_path)
            with open(cache_path, "rb") as f:
                data = f.read()
            print("大小: %.1f MB" % (len(data) / 1048576))
        else:
            print("识别为 IPA，正在提取主二进制 ...")
            data, exe, app = extract_from_ipa(path)
            if data is None:
                print("无法从 IPA 中提取可执行文件", file=sys.stderr)
                return 3
            print("App: %s" % app)
            print("可执行文件: %s (%.1f MB)" % (exe, len(data) / 1048576))
            try:
                with open(cache_path, "wb") as f:
                    f.write(data)
                print("已缓存到: %s（下次直接复用，秒开）" % cache_path)
            except Exception as exc:  # noqa: BLE001
                warn("缓存写入失败: %s" % exc)
    else:
        with open(path, "rb") as f:
            data = f.read()

    # Blob 只需要支持切片和 .find，bytes 本身就够用，不必再套一层 mmap。
    blob = Blob(data, os.path.basename(path))

    try:
        machos = load_machos(blob)
    except Exception as exc:  # noqa: BLE001
        print("Mach-O 解析失败: %s" % exc, file=sys.stderr)
        return 4
    if not machos:
        print("没有找到可解析的 Mach-O 架构", file=sys.stderr)
        return 4

    results, total_classes = analyze(machos, keywords, args.top)

    if args.dump_classes:
        with open(args.dump_classes, "w", encoding="utf-8") as f:
            for m in machos:
                for cname, methods in m.class_list():
                    f.write("%s\n" % cname)
                    for sel, types in methods:
                        f.write("    - %s  |  %s\n" % (sel, types))
        print("\n全部类与方法已写入: %s" % args.dump_classes)

    print("\n" + "=" * 68)
    print("关键词命中排名 (共 %d 个类, %d 条候选)" % (total_classes, len(results)))
    print("=" * 68)
    if not results:
        print("没有命中任何候选。可能原因：")
        print("  - 二进制被 FairPlay 加密，ObjC 元数据不可读")
        print("  - 该 slice 不是 App 主二进制")
        print("  - 关键词需要调整")
        return 1

    for i, r in enumerate(results[:args.top], 1):
        print("%3d) [%3d] %s" % (i, r["score"], r["class"]))
        print("        - %s   %s" % (r["selector"], r["types"]))

    return 0


if __name__ == "__main__":
    sys.exit(main())
