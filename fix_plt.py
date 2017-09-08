from idautils import *
from idaapi import *
from idc import *
import struct
import sys
import re

"""
Sometimes IDA fails at fixing the PLT entries, for some reason.
For example on a x86 ELF with PIE & Full-RELRO, PLT entries will look like:

    .plt.got:00000660 sub_660         proc near               ; CODE XREF: sub_BCD+28p
    .plt.got:00000660                                         ; sub_C79+82p ...
    .plt.got:00000660                 jmp     dword ptr [ebx+0Ch]
    .plt.got:00000660 sub_660         endp

I didn't find a way to fix this in the Loading options, so fixed it with this script.
Example fixed PLT entry after running the script:

    .plt.got:00000660 ; ssize_t read(int fd, void *buf, size_t nbytes)
    .plt.got:00000660 read            proc near               ; CODE XREF: sub_BCD+28p
    .plt.got:00000660                                         ; sub_C79+82p ...
    .plt.got:00000660                 jmp     ds:read_ptr[ebx]
    .plt.got:00000660 read            endp
"""

for s in Segments():
    segname = SegName(s)
    if segname == ".plt.got":
        plt_got = s
    elif segname == ".got":
        got = s

if not plt_got or not got:
    print "[-] can't find .plt_got or .got segments, WTF"
    sys.exit(0)

for funcea in list(Functions(SegStart(plt_got), SegEnd(plt_got))):
    opcodes = GetManyBytes(funcea, ItemSize(funcea))
    if GetMnem(funcea) != 'jmp' or \
       re.search("\[.*\+.*\]", GetOpnd(funcea, 0)) is None or \
       len(opcodes) < 3:
        print '[-] invalid opcodes in', FuncName(funcea)
        continue

    got_offset  = struct.unpack("<I", opcodes[2:6].ljust(4, "\x00"))[0]
    got_offset += got
    old_func_name = GetFunctionName(funcea)

    try:
        import_ea = list(DataRefsFrom(got_offset))[0]
        new_type = str(GetType(import_ea)).replace("(", old_func_name + "(", 1)

        for i, b in enumerate(struct.pack("<I", got_offset)):
            PatchByte(funcea + 2 + i, ord(b))

        MakeCode(funcea)

        SetType(funcea, new_type)
        func_name = GetFunctionName(import_ea)
        MakeName(import_ea, "__imp_" + func_name)
        MakeName(funcea, func_name)
    except Exception as e:
        print '[-]', str(e)

    print '[+] Patched %s with %s' % (old_func_name, func_name)
