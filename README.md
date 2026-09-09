# exp301-toolkit

Automation for the repetitive parts of **OffSec EXP-301 (OSED)** — Windows
user-mode exploit development. Original tooling only: methodology + scaffolds
you fill with your own target data. Authorized use only (labs, exams, your own
infrastructure).

## exp301.py — the exam loop in one CLI (stdlib-only)

```bash
python3 exp301.py cyclic 3000            # metasploit-style pattern create
python3 exp301.py offset 6f41356f        # EIP value -> offset (endian-aware)
python3 exp301.py badchars crash.bin     # memory dump vs 0x01-0xff corpus diff
python3 exp301.py egghunter W00T         # 32-byte NtAccessCheck egghunter
python3 exp301.py encode sc.bin --bad 00,0a,0d   # xor-encode + decoder stub
python3 exp301.py rop mona_rop.txt       # gadget list -> ROP chain scaffold
```

## templates/ — fill CONFIG, fire

| template | module |
|---|---|
| `stack_bof.py` | vanilla stack overflow → EIP control |
| `seh_bof.py` | SEH overwrite (nSEH short jmp + pop/pop/ret) |
| `dep_rop.py` | DEP/ASLR bypass via VirtualProtect ROP (pushad layout) |
| `format_string.py` | format string leak probe + 4×%hhn write builder |
| `rop_decoder.py` | ROP payload decoder (sub/xor in-place decode loop) |

## cheatsheets/windbg_mona.md
WinDbg commands + mona one-liners in exam order, plus the eight-step loop
checklist.

Companion repo: `web300-toolkit` (OSWE) and `OSAI-arsenal` (AI-300).
