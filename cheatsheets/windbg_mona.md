# WinDbg + mona exam cheatsheet (EXP-301)

## WinDbg essentials
```
g                        go (continue)
bp <addr>                breakpoint        bl = list, bc <n> = clear
p / t                    step over / step into
r                        registers          r eip=<addr> to set
dd esp L20               dump dwords        db = bytes, da/du = ascii/unicode
s -b 0x0 L?7fffffff 41 41 41 41   search memory for bytes
!exchain                 SEH chain          !teb for thread block
.load pykd.pyd           then: !mona ...
```

## mona one-liners, in exam order
```
!mona config -set workingfolder c:\mona\%p        # first thing, always
!mona pc 3000                                     # pattern create
!mona po 6f41356f                                 # pattern offset
!mona find -type instr -s "jmp esp" -cpb '\x00'   # code pointers, badchar-safe
!mona jmp -r esp -m <module> -cpb '\x00'          # same, module-scoped
!mona seh -cpb '\x00'                             # pop/pop/ret outside SafeSEH
!mona modules                                     # mitigations per module (ASLR/DEP/SafeSEH/NX)
!mona rop -m <module> -cpb '\x00'                 # ROP chain attempt + gadgets file
!mona compare -f c:\mona\bytearray.bin -a <esp>   # badchar diff (dump vs corpus)
!mona bytearray -cpb '\x00'                       # make the corpus file
!mona egg -t W00T                                 # egghunter
```

## Exam loop reminder
1. crash → 2. `!exchain`/EIP control → 3. offset → 4. badchars via bytearray+compare
→ 5. module pick (no ASLR/SafeSEH, badchar-clean addresses) → 6. jmp esp / SEH / ROP
→ 7. shellcode (encoded if needed) → 8. VERIFY on a fresh target before reporting
