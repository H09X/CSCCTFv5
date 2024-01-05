## Challenge - XOR 101 [Rev]

### Description

```
Just xor the key and the ct

Thats too hard for you? ok then the key is 5
```

---

### Checking the chall file

```
┌──(kali㉿M0tH3r5h1P)-[~/…/CSC/writeups/reverse/XOR_101]
└─$ file core 
core: ELF 64-bit LSB core file, x86-64, version 1 (SYSV), SVR4-style, from './broken_linked_list ct key', real uid: 1000, effective uid: 1000, real gid: 1000, effective gid: 1000, execfn: './broken_linked_list', platform: 'x86_64'
```

### Analysing

This is a core dump that was generated from the binary broken_linked_list
The description tells us to xor the key with the ct and we already got the key ```5``` so we just need to find the ct 
based on the name of the binary ``` broken_linked_list``` the ct will most likely be in the heap
Using gdb wont help here because we dont have the original binary to analyse the core dump 
therefore i decided to brute force my way into finding the ct by searching all the mappings for it
we already know part of the ct since we already know the flag format ```CSCCTF{``` and we have the key ```5```

---

### solution

```py
ord('C') ^ 5 = 70 (0x46 in hex)
```

So we need to find the mapping that have the value ```0x46```

I write a python script to do that using pwntools

```py
from pwn import *

core = Corefile("./core")

start_address = core.mappings[0].start
end_address = core.mappings[-1].stop
step_size = 0x1000

for i in range(start_address, end_address, step_size):
    try:
        data = core.read(i, step_size)
        if b'46' in data:
            print(data.strip())
            break
    except:
        print("Not here")
```

Running this we get 

```py
b'\x00\x00\x00\x00\x00\x00\x00\x00\x91\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0\xd6+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0046\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0056\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0046\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0046\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0051\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0043\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x007e\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x004d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0036\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0064\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0075\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0048\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0031\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0076\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0071\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0060\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0077\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x005a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0048\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0036\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0068\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0035\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0077\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x007c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0048\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0031\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0062\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x006c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0066\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x006c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x0064\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x006b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xe1\x01\x00\x00\x00\x00\x00\x00\xbd\xf2\xbab\x05\x00\x00\x00\xad\x89\xb7\xe0\xf7\xff\xc9\x9d\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xa0\xa6\xe3\xdf\x1d\x7f\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\xd7+\xaf+V\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x90\xd7+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00f\xe3\xdf\x1d\x7f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00@b\xe3\xdf\x1d\x7f\x00\x00!\x00\x00\x00\x00\x00\x00\x00F\x00\x00\x006\n46\xa0\xd8+\xaf+V\x00\x003\n7e\n4d\n!\x00\x00\x00\x00\x00\x00\x00V\x00\x00\x0031\n7\xc0\xd8+\xaf+V\x00\x0077\n5a\n48!\x00\x00\x00\x00\x00\x00\x00F\x00\x00\x00\n7c\n\xe0\xd8+\xaf+V\x00\x00\n6c\n66\n6!\x00\x00\x00\x00\x00\x00\x00F\x00\x00\x00\x00\x00\x00\x00\x00\xd9+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00Q\x00\x00\x00\x00\x00\x00\x00 \xd9+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00C\x00\x00\x00\x00\x00\x00\x00@\xd9+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00~\x00\x00\x00\x00\x00\x00\x00`\xd9+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00M\x00\x00\x00\x00\x00\x00\x00\x80\xd9+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x006\x00\x00\x00\x00\x00\x00\x00\xa0\xd9+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00d\x00\x00\x00\x00\x00\x00\x00\xc0\xd9+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00u\x00\x00\x00\x00\x00\x00\x00\xe0\xd9+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00H\x00\x00\x00\x00\x00\x00\x00\x00\xda+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x001\x00\x00\x00\x00\x00\x00\x00 \xda+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00v\x00\x00\x00\x00\x00\x00\x00@\xda+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00q\x00\x00\x00\x00\x00\x00\x00`\xda+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00`\x00\x00\x00\x00\x00\x00\x00\x80\xda+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00w\x00\x00\x00\x00\x00\x00\x00\xa0\xda+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00Z\x00\x00\x00\x00\x00\x00\x00\xc0\xda+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00H\x00\x00\x00\x00\x00\x00\x00\xe0\xda+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x006\x00\x00\x00\x00\x00\x00\x00\x00\xdb+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00h\x00\x00\x00\x00\x00\x00\x00 \xdb+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x005\x00\x00\x00\x00\x00\x00\x00@\xdb+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00w\x00\x00\x00\x00\x00\x00\x00`\xdb+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00|\x00\x00\x00\x00\x00\x00\x00\x80\xdb+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00H\x00\x00\x00\x00\x00\x00\x00\xa0\xdb+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x001\x00\x00\x00\x00\x00\x00\x00\xc0\xdb+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00b\x00\x00\x00\x00\x00\x00\x00\xe0\xdb+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00l\x00\x00\x00\x00\x00\x00\x00\x00\xdc+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00f\x00\x00\x00\x00\x00\x00\x00 \xdc+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00l\x00\x00\x00\x00\x00\x00\x00@\xdc+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00d\x00\x00\x00\x00\x00\x00\x00`\xdc+\xaf+V\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00!\x00\x00\x00\x00\x00\x00\x00k\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x91\x03\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

lets remove the ```\x00``` to make it more readable

```py
b'\x91\x02\x01\xa0\xd6+\xaf+V!46!56!46!46!51!43!7e!4d!36!64!75!48!31!76!71!60!77!5a!48!36!68!35!77!7c!48!31!62!6c!66!6c!64!6b\xe1\x01\xbd\xf2\xbab\x05\xad\x89\xb7\xe0\xf7\xff\xc9\x9d\xa0\xa6\xe3\xdf\x1d\x7f\xff\xff\xff\xff\x80\xd7+\xaf+V\xff\xff\xff\xff\xff\xff\xff\xff\x90\xd7+\xaf+V\xff\xff\xff\xfff\xe3\xdf\x1d\x7f@b\xe3\xdf\x1d\x7f!F6\n46\xa0\xd8+\xaf+V3\n7e\n4d\n!V31\n7\xc0\xd8+\xaf+V77\n5a\n48!F\n7c\n\xe0\xd8+\xaf+V\n6c\n66\n6!F\xd9+\xaf+V!Q \xd9+\xaf+V!C@\xd9+\xaf+V!~`\xd9+\xaf+V!M\x80\xd9+\xaf+V!6\xa0\xd9+\xaf+V!d\xc0\xd9+\xaf+V!u\xe0\xd9+\xaf+V!H\xda+\xaf+V!1 \xda+\xaf+V!v@\xda+\xaf+V!q`\xda+\xaf+V!`\x80\xda+\xaf+V!w\xa0\xda+\xaf+V!Z\xc0\xda+\xaf+V!H\xe0\xda+\xaf+V!6\xdb+\xaf+V!h \xdb+\xaf+V!5@\xdb+\xaf+V!w`\xdb+\xaf+V!|\x80\xdb+\xaf+V!H\xa0\xdb+\xaf+V!1\xc0\xdb+\xaf+V!b\xe0\xdb+\xaf+V!l\xdc+\xaf+V!f \xdc+\xaf+V!l@\xdc+\xaf+V!d`\xdc+\xaf+V!k\x91\x03\x02'
```

We get this and theres an intresting sequence here ```46!56!46!46!51!43!7e!4d!36!64!75!48!31!76!71!60!77!5a!48!36!68!35!77!7c!48!31!62!6c!66!6c!64!6b```
This looks like the ciphertext lets xor it with 5

```py
ct = [0x46,0x56,0x46,0x46,0x51,0x43,0x7e,0x4d,0x36,0x64,0x75,0x48,0x31,0x76,0x71,0x60,0x77,0x5a,0x48,0x36,0x68,0x35,0x77,0x7c,0x48,0x31,0x62,0x6c,0x66,0x6c,0x64,0x6b]
key = 5

for i in ct:
    print(chr(key ^ i) , end = "")
```

running this we get ```CSCCTF{H3apM4ster_M3m0ryM4gician```

---

Flag = ```CSCCTF{H3apM4ster_M3m0ryM4gician}```