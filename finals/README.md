# Final

## 100 (Upsolve)
category: Reverse
- attachment: [100](100/original/100)

From the binary, we can see there are more than 100 function. And the hint from problem description said that "just run it". When I decompiled it using IDA I see the pseudocode inside main function:
```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // ST14_4
  int i; // [rsp+Ch] [rbp-424h]
  int j; // [rsp+Ch] [rbp-424h]
  signed int k; // [rsp+Ch] [rbp-424h]
  int v8; // [rsp+10h] [rbp-420h]
  char v9; // [rsp+20h] [rbp-410h]
  char s[520]; // [rsp+220h] [rbp-210h]
  unsigned __int64 v11; // [rsp+428h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  prepare();
  fgets(s, 512, stdin);
  v8 = strlen(s) >> 1;
  unhex(s);
  for ( i = 0; i < v8; ++i )
  {
    v3 = rand() % 100;
    ((void (__fastcall *)(_QWORD, _QWORD, _QWORD))dDddd[v3])(
      (unsigned int)s[i],
      (unsigned int)*((char *)cCccc + i),
      (unsigned int)i);
  }
  for ( j = bBbbb; j < v8; ++j )
    aAaaa[j] ^= s[j];
  for ( k = 0; k <= 7; ++k )
  {
    if ( k & 1 )
      base64_decode(&v9, aAaaa);
    else
      base64_decode(aAaaa, &v9);
  }
  if ( bBbbb )
    puts("Try again.");
  else
    printf("Arkav5{%s}\n", aAaaa);
  return 0;
}
```
And inside prepare function:
```
__int64 (__fastcall *prepare())()
{
  __int64 (__fastcall *result)(); // rax

  srand(1337u);
  dDddd[0] = (__int64)fFfff0;
  qword_60A2A8 = (__int64)fFfff1;
  qword_60A2B0 = (__int64)fFfff2;
  qword_60A2B8 = (__int64)fFfff3;
  qword_60A2C0 = (__int64)fFfff4;
  qword_60A2C8 = (__int64)fFfff5;
  qword_60A2D0 = (__int64)fFfff6;
  qword_60A2D8 = (__int64)fFfff7;
  qword_60A2E0 = (__int64)fFfff8;
  qword_60A2E8 = (__int64)fFfff9;
  qword_60A2F0 = (__int64)fFfff10;
  qword_60A2F8 = (__int64)fFfff11;
  qword_60A300 = (__int64)fFfff12;
  qword_60A308 = (__int64)fFfff13;
  qword_60A310 = (__int64)fFfff14;
  qword_60A318 = (__int64)fFfff15;
  qword_60A320 = (__int64)fFfff16;
  qword_60A328 = (__int64)fFfff17;
  qword_60A330 = (__int64)fFfff18;
  qword_60A338 = (__int64)fFfff19;
  qword_60A340 = (__int64)fFfff20;
  qword_60A348 = (__int64)fFfff21;
  qword_60A350 = (__int64)fFfff22;
  qword_60A358 = (__int64)fFfff23;
  qword_60A360 = (__int64)fFfff24;
  qword_60A368 = (__int64)fFfff25;
  qword_60A370 = (__int64)fFfff26;
  qword_60A378 = (__int64)fFfff27;
  qword_60A380 = (__int64)fFfff28;
  qword_60A388 = (__int64)fFfff29;
  qword_60A390 = (__int64)fFfff30;
  qword_60A398 = (__int64)fFfff31;
  qword_60A3A0 = (__int64)fFfff32;
  qword_60A3A8 = (__int64)fFfff33;
  qword_60A3B0 = (__int64)fFfff34;
  qword_60A3B8 = (__int64)fFfff35;
  qword_60A3C0 = (__int64)fFfff36;
  qword_60A3C8 = (__int64)fFfff37;
  qword_60A3D0 = (__int64)fFfff38;
  qword_60A3D8 = (__int64)fFfff39;
  qword_60A3E0 = (__int64)fFfff40;
  qword_60A3E8 = (__int64)fFfff41;
  qword_60A3F0 = (__int64)fFfff42;
  qword_60A3F8 = (__int64)fFfff43;
  qword_60A400 = (__int64)fFfff44;
  qword_60A408 = (__int64)fFfff45;
  qword_60A410 = (__int64)fFfff46;
  qword_60A418 = (__int64)fFfff47;
  qword_60A420 = (__int64)fFfff48;
  qword_60A428 = (__int64)fFfff49;
  qword_60A430 = (__int64)fFfff50;
  qword_60A438 = (__int64)fFfff51;
  qword_60A440 = (__int64)fFfff52;
  qword_60A448 = (__int64)fFfff53;
  qword_60A450 = (__int64)fFfff54;
  qword_60A458 = (__int64)fFfff55;
  qword_60A460 = (__int64)fFfff56;
  qword_60A468 = (__int64)fFfff57;
  qword_60A470 = (__int64)fFfff58;
  qword_60A478 = (__int64)fFfff59;
  qword_60A480 = (__int64)fFfff60;
  qword_60A488 = (__int64)fFfff61;
  qword_60A490 = (__int64)fFfff62;
  qword_60A498 = (__int64)fFfff63;
  qword_60A4A0 = (__int64)fFfff64;
  qword_60A4A8 = (__int64)fFfff65;
  qword_60A4B0 = (__int64)fFfff66;
  qword_60A4B8 = (__int64)fFfff67;
  qword_60A4C0 = (__int64)fFfff68;
  qword_60A4C8 = (__int64)fFfff69;
  qword_60A4D0 = (__int64)fFfff70;
  qword_60A4D8 = (__int64)fFfff71;
  qword_60A4E0 = (__int64)fFfff72;
  qword_60A4E8 = (__int64)fFfff73;
  qword_60A4F0 = (__int64)fFfff74;
  qword_60A4F8 = (__int64)fFfff75;
  qword_60A500 = (__int64)fFfff76;
  qword_60A508 = (__int64)fFfff77;
  qword_60A510 = (__int64)fFfff78;
  qword_60A518 = (__int64)fFfff79;
  qword_60A520 = (__int64)fFfff80;
  qword_60A528 = (__int64)fFfff81;
  qword_60A530 = (__int64)fFfff82;
  qword_60A538 = (__int64)fFfff83;
  qword_60A540 = (__int64)fFfff84;
  qword_60A548 = (__int64)fFfff85;
  qword_60A550 = (__int64)fFfff86;
  qword_60A558 = (__int64)fFfff87;
  qword_60A560 = (__int64)fFfff88;
  qword_60A568 = (__int64)fFfff89;
  qword_60A570 = (__int64)fFfff90;
  qword_60A578 = (__int64)fFfff91;
  qword_60A580 = (__int64)fFfff92;
  qword_60A588 = (__int64)fFfff93;
  qword_60A590 = (__int64)fFfff94;
  qword_60A598 = (__int64)fFfff95;
  qword_60A5A0 = (__int64)fFfff96;
  qword_60A5A8 = (__int64)fFfff97;
  qword_60A5B0 = (__int64)fFfff98;
  result = fFfff99;
  qword_60A5B8 = (__int64)fFfff99;
  return result;
}
```

And check some sample of 100 hundred fFfff function:
```
char *__fastcall fFfff26(char a1, unsigned __int8 a2, int a3)
{
  int v3; // eax
  int v4; // ebx
  int v5; // eax
  int v6; // ebx
  int v7; // eax
  int v8; // ebx
  char v9; // al
  char v10; // al
  char *result; // rax
  int v12; // [rsp+4h] [rbp-1Ch]
  char v13; // [rsp+8h] [rbp-18h]

  v12 = a3;
  v3 = rand();
  v4 = a2 - ((unsigned __int8)(((unsigned int)(v3 >> 31) >> 24) + v3) - ((unsigned int)(v3 >> 31) >> 24));
  v5 = rand();
  v6 = v4 + (unsigned __int8)(((unsigned int)(v5 >> 31) >> 24) + v5) - ((unsigned int)(v5 >> 31) >> 24);
  v7 = rand();
  v8 = ((unsigned __int8)(((unsigned int)(v7 >> 31) >> 24) + v7) - ((unsigned int)(v7 >> 31) >> 24)) ^ v6;
  v9 = rand();
  v13 = (v8 ^ v9) + rand();
  LOBYTE(v8) = rand();
  v10 = rand();
  result = (char *)eEeee(a1, v13, v10, v8);
  if ( (_DWORD)result )
  {
    result = aAaaa;
    aAaaa[v12] = a1 ^ v13;
  }
  return result;
}
```

From one of fFfff function they call eEeee function. When we check that function
```
signed __int64 __fastcall eEeee(char a1, char a2, char a3, char a4)
{
  if ( (a4 ^ (a3 + a1)) != a2 )
    return 0LL;
  --bBbbb;
  return 1LL;
}
```
When we look again at main function. We win if bBbbb equal to 0. And from the prepare dDddd[i] store pointer to fFfff{i} function and in the main they call dDddd\[i]() so it refers to fFfff{i}. The other point is, they validate input **char by char**. Time to brute force. But, we didnt have enough info. But, we can patch the binary to make it happen.

Copy the binary first
```
$ cp 100 100_patch
```
The idea is to change this line:
```
if ( bBbbb )
    puts("Try again.");
  else
    printf("Arkav5{%s}\n", aAaaa);
```
Into
```
if ( !bBbbb )
    puts("Try again.");
  else
    printf("%d", bBbbb);
```
here are my initial patch script
`patch.py`
```
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
```
And here are my solution script
`brute_input.py`
```
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
```
But I after 5th digit, I failed. I try to debug it using gdb. And i figure out in validation function eEeee
```
   0x00000000004009a3 <+42>:    cmp    edx,eax
```
it should compare byte instead of word(word here means 4 byte). So I patch both binary to change `cmp edx,eax` into `cmp dl,al`.
`patch.py`
```
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
```

`patch_asli.py`
```
def binary_patching(pattern, patch):
    inputstream = open('100', 'r').read()
    assert inputstream.count(pattern) <= 1
    result = inputstream.replace(pattern, patch)
    outputfile = open('100', 'w')
    outputfile.write(result)
    outputfile.close()


pattern = "9\302u\026\213\005\263\226 "
patch = "8\302u\026\213\005\263\226 "
binary_patching(pattern, patch)
```

Run the script again and find the right input:
```
bfb6f9016764fadb8c0e3f0a956e7757c3e6b0fbd0d51ed953a59c936a036e0bc73c8072eceaeac5990462afb40e2c5be163bd22defab34901aa4396f979dfe77f275c9336d9b536eaf6e367b012bcecee252520bc2e74e89c245156a21c327c4f166cefd52e8046cbd8372af9db7146c5476ece4f50664e50da21cdc1904b6dd1fc009fe2a72641a145a4f9f552d076085e8454bc9d5967ff10c93dae5f5a4617dcf80b6242fc4f9837a41b042b30fc643d6b624824ff1d271f1eb0a0dc5c82f58617d8dbd5b295898ac774abd1c6e14b49fbd2e8da995d7a63d2e445b4eac96f674dc0293632ce03f9abacea93b3d1fb72167101a671c32fc9b428
```

Then run it in my shell
```
$ ./100
bfb6f9016764fadb8c0e3f0a956e7757c3e6b0fbd0d51ed953a59c936a036e0bc73c8072eceaeac5990462afb40e2c5be163bd22defab34901aa4396f979dfe77f275c9336d9b536eaf6e367b012bcecee252520bc2e74e89c245156a21c327c4f166cefd52e8046cbd8372af9db7146c5476ece4f50664e50da21cdc1904b6dd1fc009fe2a72641a145a4f9f552d076085e8454bc9d5967ff10c93dae5f5a4617dcf80b6242fc4f9837a41b042b30fc643d6b624824ff1d271f1eb0a0dc5c82f58617d8dbd5b295898ac774abd1c6e14b49fbd2e8da995d7a63d2e445b4eac96f674dc0293632ce03f9abacea93b3d1fb72167101a671c32fc9b428
Arkav5{m4k3_17_4lw4Y5_tRU3}
```

flag: `Arkav5{m4k3_17_4lw4Y5_tRU3}`

## Hangman
Bug terdapat di srand(time(0)) cukup menyamakan dengan time di server, dan kita mendapatkan semua kata2. 
Berikut adalah payload saya
They use epoch time (`srand(time(0))`)