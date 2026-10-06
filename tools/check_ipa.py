# -*- coding: utf-8 -*-
"""看一下 IPA 的内部结构，确认能不能正常提取主二进制。"""
import os
import sys
import zipfile

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

p = sys.argv[1] if len(sys.argv) > 1 else \
    r"C:\Users\陈炜坤\Desktop\wx-antirevoke\ipa\com.tencent.xin_8.0.79_maclub.net.ipa"

print("路径:", p)
print("存在:", os.path.exists(p))
if not os.path.exists(p):
    sys.exit(1)
print("大小: %.1f MB" % (os.path.getsize(p) / 1048576))
print("是 zip:", zipfile.is_zipfile(p))

with zipfile.ZipFile(p) as z:
    infos = z.infolist()
    names = [i.filename for i in infos]
    print("条目数:", len(names))

    tops = []
    seen = set()
    for n in names:
        t = n.split("/")[0]
        if t not in seen:
            seen.add(t)
            tops.append(t)
    print("\n--- 顶层条目 ---")
    for t in tops[:30]:
        print("  ", t)

    print("\n--- Payload 下的 .app ---")
    apps = sorted({n.split("/")[1] for n in names
                   if n.startswith("Payload/") and len(n.split("/")) > 2})
    for a in apps[:10]:
        print("  ", a)

    for a in apps[:3]:
        prefix = "Payload/%s/" % a
        subs = [n[len(prefix):] for n in names
                if n.startswith(prefix) and "/" not in n[len(prefix):]]
        print("\n--- [%s] 顶层 %d 个条目 ---" % (a, len(subs)))
        for s in subs[:20]:
            print("   ", s)

        # 找最大的那个文件，八成就是主二进制
        cand = []
        for i in infos:
            if i.filename.startswith(prefix) and "/" not in i.filename[len(prefix):]:
                cand.append((i.file_size, i.filename[len(prefix):]))
        cand.sort(reverse=True)
        print("   最大的几个（很可能是主二进制）:")
        for sz, nm in cand[:5]:
            print("      %8.1f MB  %s" % (sz / 1048576, nm))
