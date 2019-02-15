from pwn import *
context(arch='amd64', bits=64)

def binary_patching(pattern, patch):
	inputstream = open('100_patch', 'r').read()
	assert inputstream.count(pattern) <= 1
	result = inputstream.replace(pattern, patch)
	outputfile = open('100_patch', 'w')
	outputfile.write(result)
	outputfile.close()



# patch 1, ubah jne jadi je
pattern1 = "u\032H\215\065W$ "
patch1 = chr(0x74) + pattern1[1:]
binary_patching(pattern1, patch1)


# patch 2, ubah Arkav5{%s} jadi Arkav5{%d}
pattern2 = "Arkav5{%s}"
patch2 = "Arkav5{%d}"
binary_patching(pattern2, patch2)

# patch 3, ubah aAaaa jadi bBbbb
pattern3 = "H\215\065" + p32(0x202457)
patch3 = "H\215\065" + p32(0x202417)
binary_patching(pattern3, patch3)

# patch 4, ubah <lea rsi,[rip+0x202417]> jadi <mov rsi,[rip+0x202417]>
pattern4 = asm('lea rsi,[rip+0x202417]')
patch4 = asm('mov rsi,[rip+0x202417]')
binary_patching(pattern4, patch4)

# masih pengin yang enak wkwkwk, ubah "Arkav5{%d}" jadi "%d\n\x00"
pattern5 = "Arkav5{%d}"
patch5 = "%d\n".ljust(pattern5.__len__(), '\x00')
binary_patching(pattern5, patch5)

# patch as a binary asli
pattern6 = "9\302u\026\213\005\263\226 "
patch6 = "8\302u\026\213\005\263\226 "
binary_patching(pattern6, patch6)
