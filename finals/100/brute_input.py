from pwn import *

last_val = 252
ans = ''

while last_val > 0:
	for i in range(256):
		guess = ans + hex(0x100 + i)[-2:]
		r = process('100_patch')
		r.sendline(guess)
		resp = int(r.recvline())
		if resp != last_val:
			last_val = resp
			ans = guess
			r.close()
			break
		r.close()
	print ans