## Challenge - Possible Writer [Rev]

### Description

```
Its time for revenge 😉
```

---

### Checking the chall files

```
┌──(kali㉿M0tH3r5h1P)-[~/…/CSC/writeups/reverse/possible_writer]
└─$ ls
hash  main
                                                                                                                                                                                                                                            
┌──(kali㉿M0tH3r5h1P)-[~/…/CSC/writeups/reverse/possible_writer]
└─$ file main       
main: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=e79fc19b37630b357d6f1d69a18651bdeec7c9ac, for GNU/Linux 3.2.0, not stripped
                                                                                                                                                                                                                                            
┌──(kali㉿M0tH3r5h1P)-[~/…/CSC/writeups/reverse/possible_writer]
└─$ cat hash      
d9317ef25cedec862039b257cd83b1b536d3ae272ec4b2dde9b9d05e8169455a
```

here we ca see we have 2 files ```main``` which is the binary and ```hash``` which we dont know what it is for yet

---

### Reversing the Binary 

#### Analyzing Main

```c
undefined8 main(void)

{
  int iVar1;
  undefined8 uVar2;
  char *pcVar3;
  time_t tVar4;
  int local_16c;
  byte local_168 [32];
  undefined local_148 [32];
  char local_128 [264];
  int local_20;
  int local_1c;
  FILE *local_18;
  int local_10;
  int local_c;
  
  local_18 = fopen("/proc/self/status","r");
  if (local_18 == (FILE *)0x0) {
    fwrite("Failed to open status file\n",1,0x1b,stderr);
    uVar2 = 1;
  }
  else {
    do {
      pcVar3 = fgets(local_128,0x100,local_18);
      if (pcVar3 == (char *)0x0) {
        fclose(local_18);
        tVar4 = time((time_t *)0x0);
        srand((uint)tVar4);
        iVar1 = rand();
        local_1c = iVar1 % 0x26ad + 10000;
        FUN_00101269(&DAT_0039b008,local_148,local_1c);
        printf("Enter hash (in hexadecimal format): ");
        for (local_c = 0; local_c < 0x20; local_c = local_c + 1) {
          __isoc99_scanf("%2hhx",local_168 + local_c);
        }
        printf("Entered hash: ");
        for (local_10 = 0; local_10 < 0x20; local_10 = local_10 + 1) {
          printf("%02x",(ulong)local_168[local_10]);
        }
        putchar(10);
        local_20 = memcmp(local_148,local_168,0x20);
        if (local_20 == 0) {
          Fun_1(local_148,local_1c);
        }
        return 0;
      }
      iVar1 = strncmp(local_128,"TracerPid",9);
    } while (((iVar1 != 0) ||
             (iVar1 = __isoc99_sscanf(local_128,"TracerPid:\t%d",&local_16c), iVar1 != 1)) ||
            (local_16c == 0));
    fclose(local_18);
    uVar2 = 0;
  }
  return uVar2;
}

```

**Analysis:** This main first checks if the program is being debugged if not it generates a random number then calls the funtion ```FUN_00101269``` and prompts th user to enter a hash if the user unput and the value that the function reurns match it calls another function

#### Analyzing FUN_00101269

```c

void FUN_00101269(undefined8 param_1,uchar *param_2,int param_3)

{
  long lVar1;
  uchar *md;
  undefined *data;
  FILE *pFVar2;
  int iVar3;
  size_t sVar4;
  undefined8 uStack_d0;
  undefined auStack_c8 [12];
  int local_bc;
  uchar *local_b8;
  undefined8 local_b0;
  SHA256_CTX local_a8;
  size_t local_38;
  undefined *local_30;
  long local_28;
  FILE *local_20;
  
  uStack_d0 = 0x39a6c0;
  local_bc = param_3;
  local_b8 = param_2;
  local_b0 = param_1;
  system("objdump -d main | awk \'/<main>:/,/ret/\' > temp");
  uStack_d0 = 0x39a6d9;
  local_20 = fopen("temp","r");
  if (local_20 == (FILE *)0x0) {
    uStack_d0 = 0x39a6f3;
    puts("Error opening file.");
  }
  else {
    uStack_d0 = 0x39a707;
    iVar3 = SHA256_Init(&local_a8);
    pFVar2 = local_20;
    if (iVar3 == 0) {
      uStack_d0 = 0x39a71a;
      puts("Error initializing SHA256 context.");
      uStack_d0 = 0x39a726;
      fclose(local_20);
    }
    else {
      local_28 = (long)local_bc + -1;
      lVar1 = (((long)local_bc + 0xfU) / 0x10) * -0x10;
      local_30 = auStack_c8 + lVar1;
      sVar4 = (size_t)local_bc;
      *(undefined8 *)(auStack_c8 + lVar1 + -8) = 0x39a782;
      sVar4 = fread(auStack_c8 + lVar1,1,sVar4,pFVar2);
      data = local_30;
      local_38 = sVar4;
      if (sVar4 == (long)local_bc) {
        *(undefined8 *)(auStack_c8 + lVar1 + -8) = 0x39a7ce;
        iVar3 = SHA256_Update(&local_a8,data,sVar4);
        md = local_b8;
        if (iVar3 == 0) {
          *(undefined8 *)(auStack_c8 + lVar1 + -8) = 0x39a7e1;
          puts("Error updating SHA256 context.");
          pFVar2 = local_20;
          *(undefined8 *)(auStack_c8 + lVar1 + -8) = 0x39a7ed;
          fclose(pFVar2);
        }
        else {
          *(undefined8 *)(auStack_c8 + lVar1 + -8) = 0x39a808;
          iVar3 = SHA256_Final(md,&local_a8);
          pFVar2 = local_20;
          if (iVar3 == 0) {
            *(undefined8 *)(auStack_c8 + lVar1 + -8) = 0x39a81b;
            puts("Error finalizing SHA256 hash.");
            pFVar2 = local_20;
            *(undefined8 *)(auStack_c8 + lVar1 + -8) = 0x39a827;
            fclose(pFVar2);
          }
          else {
            *(undefined8 *)(auStack_c8 + lVar1 + -8) = 0x39a835;
            fclose(pFVar2);
            *(undefined8 *)(auStack_c8 + lVar1 + -8) = 0x39a844;
            system("rm temp");
          }
        }
      }
      else {
        *(undefined8 *)(auStack_c8 + lVar1 + -8) = 0x39a7a3;
        puts("Error: Unable to read bytes from the file.");
        pFVar2 = local_20;
        *(undefined8 *)(auStack_c8 + lVar1 + -8) = 0x39a7af;
        fclose(pFVar2);
      }
    }
  }
  return;
}
```

**Analysis:** This function calculates the hash of the first k bytes of the main function with k being the random number generated

---

### Solution 

After understanding the code i know what i should do to get the flag 
because we already have a hash we need to find the random number that generates that hash and set it as the random number but before that we have to bypass the anti debugger

Lets find the random number by brute forcing it

```
┌──(kali㉿M0tH3r5h1P)-[~/…/CSC/writeups/reverse/possible_writer]
└─$ objdump -d main | awk '/<main>:/,/ret/' > temp
```

this will disassemble the main function and put it in a file named temp 
now lets brute force it

```py
import hashlib

def calculate_sha256(file_path, k):
    with open(file_path, 'rb') as file:
        data = file.read(k)
        sha256_hash = hashlib.sha256(data).hexdigest()
        return sha256_hash

file_path = 'temp'
for i in range(100000):
    sha256_result = calculate_sha256(file_path, i)
    if sha256_result == 'd9317ef25cedec862039b257cd83b1b536d3ae272ec4b2dde9b9d05e8169455a':
        print(f"SHA256 hash of the first {i} bytes in the file: {sha256_result}")
```

running this program will output ```845```
now we have everything we need to solve the challenge lets fire up gdb

we set up a breakpoint at main so we dont trigger the anti debugger 

```c
┌──(kali㉿M0tH3r5h1P)-[~/…/CSC/writeups/reverse/possible_writer]
└─$ gdb-peda main 
Reading symbols from main...
(No debugging symbols found in main)
gdb-peda$ b main
Breakpoint 1 at 0x29a856
gdb-peda$ set follow-fork-mode parent
gdb-peda$ r
```

after running the binary we disas the main to see where does the anti debugger work

```c
gdb-peda$ disas main
Dump of assembler code for function main:
   0x00005555557ee852 <+0>:     push   rbp
   0x00005555557ee853 <+1>:     mov    rbp,rsp
=> 0x00005555557ee856 <+4>:     sub    rsp,0x180
   0x00005555557ee85d <+11>:    mov    DWORD PTR [rbp-0x174],edi
   0x00005555557ee863 <+17>:    mov    QWORD PTR [rbp-0x180],rsi
   0x00005555557ee86a <+24>:    lea    rax,[rip+0x7ce]        # 0x5555557ef03f
   0x00005555557ee871 <+31>:    mov    rsi,rax
   0x00005555557ee874 <+34>:    lea    rax,[rip+0x882]        # 0x5555557ef0fd
   0x00005555557ee87b <+41>:    mov    rdi,rax
   0x00005555557ee87e <+44>:    call   0x5555555550e0 <fopen@plt>
   0x00005555557ee883 <+49>:    mov    QWORD PTR [rbp-0x10],rax
   0x00005555557ee887 <+53>:    cmp    QWORD PTR [rbp-0x10],0x0
   0x00005555557ee88c <+58>:    jne    0x5555557ee92b <main+217>
   0x00005555557ee892 <+64>:    mov    rax,QWORD PTR [rip+0x32827]        # 0x5555558210c0 <stderr@GLIBC_2.2.5>
   0x00005555557ee899 <+71>:    mov    rcx,rax
   0x00005555557ee89c <+74>:    mov    edx,0x1b
   0x00005555557ee8a1 <+79>:    mov    esi,0x1
   0x00005555557ee8a6 <+84>:    lea    rax,[rip+0x862]        # 0x5555557ef10f
   0x00005555557ee8ad <+91>:    mov    rdi,rax
   0x00005555557ee8b0 <+94>:    call   0x555555555150 <fwrite@plt>
   0x00005555557ee8b5 <+99>:    mov    eax,0x1
   0x00005555557ee8ba <+104>:   jmp    0x5555557eea99 <main+583>
   0x00005555557ee8bf <+109>:   lea    rax,[rbp-0x120]
   0x00005555557ee8c6 <+116>:   mov    edx,0x9
   0x00005555557ee8cb <+121>:   lea    rcx,[rip+0x859]        # 0x5555557ef12b
   0x00005555557ee8d2 <+128>:   mov    rsi,rcx
   0x00005555557ee8d5 <+131>:   mov    rdi,rax
   0x00005555557ee8d8 <+134>:   call   0x555555555060 <strncmp@plt>
   0x00005555557ee8dd <+139>:   test   eax,eax
   0x00005555557ee8df <+141>:   jne    0x5555557ee92b <main+217>
   0x00005555557ee8e1 <+143>:   lea    rdx,[rbp-0x164]
   0x00005555557ee8e8 <+150>:   lea    rax,[rbp-0x120]
   0x00005555557ee8ef <+157>:   lea    rcx,[rip+0x83f]        # 0x5555557ef135
   0x00005555557ee8f6 <+164>:   mov    rsi,rcx
   0x00005555557ee8f9 <+167>:   mov    rdi,rax
   0x00005555557ee8fc <+170>:   mov    eax,0x0
   0x00005555557ee901 <+175>:   call   0x5555555550b0 <__isoc99_sscanf@plt>
   0x00005555557ee906 <+180>:   cmp    eax,0x1
   0x00005555557ee909 <+183>:   jne    0x5555557ee92b <main+217>
   0x00005555557ee90b <+185>:   mov    eax,DWORD PTR [rbp-0x164]
   0x00005555557ee911 <+191>:   test   eax,eax
   0x00005555557ee913 <+193>:   je     0x5555557ee92b <main+217>
   0x00005555557ee915 <+195>:   mov    rax,QWORD PTR [rbp-0x10]
   0x00005555557ee919 <+199>:   mov    rdi,rax
   0x00005555557ee91c <+202>:   call   0x5555555550c0 <fclose@plt>
   0x00005555557ee921 <+207>:   mov    eax,0x0
   0x00005555557ee926 <+212>:   jmp    0x5555557eea99 <main+583>
   0x00005555557ee92b <+217>:   mov    rdx,QWORD PTR [rbp-0x10]
   0x00005555557ee92f <+221>:   lea    rax,[rbp-0x120]
   0x00005555557ee936 <+228>:   mov    esi,0x100
   0x00005555557ee93b <+233>:   mov    rdi,rax
   0x00005555557ee93e <+236>:   call   0x555555555130 <fgets@plt>
   0x00005555557ee943 <+241>:   test   rax,rax
   0x00005555557ee946 <+244>:   jne    0x5555557ee8bf <main+109>
   0x00005555557ee94c <+250>:   mov    rax,QWORD PTR [rbp-0x10]
   0x00005555557ee950 <+254>:   mov    rdi,rax
   0x00005555557ee953 <+257>:   call   0x5555555550c0 <fclose@plt>
   0x00005555557ee958 <+262>:   mov    edi,0x0
   0x00005555557ee95d <+267>:   call   0x555555555090 <time@plt>
   0x00005555557ee962 <+272>:   mov    edi,eax
   0x00005555557ee964 <+274>:   call   0x5555555550a0 <srand@plt>
   0x00005555557ee969 <+279>:   call   0x555555555040 <rand@plt>
   0x00005555557ee96e <+284>:   movsxd rdx,eax
   0x00005555557ee971 <+287>:   imul   rdx,rdx,0x34f3fa1b
   0x00005555557ee978 <+294>:   shr    rdx,0x20
   0x00005555557ee97c <+298>:   sar    edx,0xb
   0x00005555557ee97f <+301>:   mov    ecx,eax
   0x00005555557ee981 <+303>:   sar    ecx,0x1f
   0x00005555557ee984 <+306>:   sub    edx,ecx
   0x00005555557ee986 <+308>:   imul   ecx,edx,0x26ad
   0x00005555557ee98c <+314>:   sub    eax,ecx
   0x00005555557ee98e <+316>:   mov    edx,eax
   0x00005555557ee990 <+318>:   lea    eax,[rdx+0x2710]
   0x00005555557ee996 <+324>:   mov    DWORD PTR [rbp-0x14],eax
   0x00005555557ee999 <+327>:   mov    edx,DWORD PTR [rbp-0x14]
   0x00005555557ee99c <+330>:   lea    rax,[rbp-0x140]
   0x00005555557ee9a3 <+337>:   mov    rsi,rax
   0x00005555557ee9a6 <+340>:   lea    rax,[rip+0x65b]        # 0x5555557ef008
   0x00005555557ee9ad <+347>:   mov    rdi,rax
   0x00005555557ee9b0 <+350>:   call   0x5555557ee68b <FUN_00101269>
   0x00005555557ee9b5 <+355>:   lea    rax,[rip+0x78c]        # 0x5555557ef148
   0x00005555557ee9bc <+362>:   mov    rdi,rax
   0x00005555557ee9bf <+365>:   mov    eax,0x0
   0x00005555557ee9c4 <+370>:   call   0x555555555030 <printf@plt>
   0x00005555557ee9c9 <+375>:   mov    DWORD PTR [rbp-0x4],0x0
   0x00005555557ee9d0 <+382>:   jmp    0x5555557ee9fc <main+426>
   0x00005555557ee9d2 <+384>:   lea    rdx,[rbp-0x160]
   0x00005555557ee9d9 <+391>:   mov    eax,DWORD PTR [rbp-0x4]
   0x00005555557ee9dc <+394>:   cdqe
   0x00005555557ee9de <+396>:   add    rax,rdx
   0x00005555557ee9e1 <+399>:   mov    rsi,rax
   0x00005555557ee9e4 <+402>:   lea    rax,[rip+0x782]        # 0x5555557ef16d
   0x00005555557ee9eb <+409>:   mov    rdi,rax
   0x00005555557ee9ee <+412>:   mov    eax,0x0
   0x00005555557ee9f3 <+417>:   call   0x5555555550d0 <__isoc99_scanf@plt>
   0x00005555557ee9f8 <+422>:   add    DWORD PTR [rbp-0x4],0x1
   0x00005555557ee9fc <+426>:   cmp    DWORD PTR [rbp-0x4],0x1f
   0x00005555557eea00 <+430>:   jle    0x5555557ee9d2 <main+384>
   0x00005555557eea02 <+432>:   lea    rax,[rip+0x76a]        # 0x5555557ef173
   0x00005555557eea09 <+439>:   mov    rdi,rax
   0x00005555557eea0c <+442>:   mov    eax,0x0
   0x00005555557eea11 <+447>:   call   0x555555555030 <printf@plt>
   0x00005555557eea16 <+452>:   mov    DWORD PTR [rbp-0x8],0x0
   0x00005555557eea1d <+459>:   jmp    0x5555557eea49 <main+503>
   0x00005555557eea1f <+461>:   mov    eax,DWORD PTR [rbp-0x8]
   0x00005555557eea22 <+464>:   cdqe
   0x00005555557eea24 <+466>:   movzx  eax,BYTE PTR [rbp+rax*1-0x160]
   0x00005555557eea2c <+474>:   movzx  eax,al
   0x00005555557eea2f <+477>:   mov    esi,eax
   0x00005555557eea31 <+479>:   lea    rax,[rip+0x74a]        # 0x5555557ef182
   0x00005555557eea38 <+486>:   mov    rdi,rax
   0x00005555557eea3b <+489>:   mov    eax,0x0
   0x00005555557eea40 <+494>:   call   0x555555555030 <printf@plt>
   0x00005555557eea45 <+499>:   add    DWORD PTR [rbp-0x8],0x1
   0x00005555557eea49 <+503>:   cmp    DWORD PTR [rbp-0x8],0x1f
   0x00005555557eea4d <+507>:   jle    0x5555557eea1f <main+461>
   0x00005555557eea4f <+509>:   mov    edi,0xa
   0x00005555557eea54 <+514>:   call   0x555555555100 <putchar@plt>
   0x00005555557eea59 <+519>:   lea    rcx,[rbp-0x160]
   0x00005555557eea60 <+526>:   lea    rax,[rbp-0x140]
   0x00005555557eea67 <+533>:   mov    edx,0x20
   0x00005555557eea6c <+538>:   mov    rsi,rcx
   0x00005555557eea6f <+541>:   mov    rdi,rax
   0x00005555557eea72 <+544>:   call   0x555555555050 <memcmp@plt>
   0x00005555557eea77 <+549>:   mov    DWORD PTR [rbp-0x18],eax
   0x00005555557eea7a <+552>:   cmp    DWORD PTR [rbp-0x18],0x0
   0x00005555557eea7e <+556>:   jne    0x5555557eea94 <main+578>
   0x00005555557eea80 <+558>:   mov    edx,DWORD PTR [rbp-0x14]
   0x00005555557eea83 <+561>:   lea    rax,[rbp-0x140]
   0x00005555557eea8a <+568>:   mov    esi,edx
   0x00005555557eea8c <+570>:   mov    rdi,rax
   0x00005555557eea8f <+573>:   call   0x5555557ee46a <Fun_1>
   0x00005555557eea94 <+578>:   mov    eax,0x0
   0x00005555557eea99 <+583>:   leave
   0x00005555557eea9a <+584>:   ret
End of assembler dump.
```

after reading this multipite time i figured out that the test is at address ```0x00005555557ee943```
so we set a breakpoint there and continue the program 

```c
[----------------------------------registers-----------------------------------]
RAX: 0x7fffffffdc10 ("Name:\tmain\n")
RBX: 0x7fffffffde48 --> 0x7fffffffe1b9 ("/home/kali/Downloads/challenges/CSC/writeups/reverse/possible_writer/main")
RCX: 0xa6e69616d093a65 ('e:\tmain\n')
RDX: 0xb ('\x0b')
RSI: 0x69616d093a656d61 ('ame:\tmai')
RDI: 0x555555822380 --> 0x0 
RBP: 0x7fffffffdd30 --> 0x1 
RSP: 0x7fffffffdbb0 --> 0x7fffffffde48 --> 0x7fffffffe1b9 ("/home/kali/Downloads/challenges/CSC/writeups/reverse/possible_writer/main")
RIP: 0x5555557ee943 (<main+241>:        test   rax,rax)
R8 : 0x55555582248b ("Umask:\t0022\nState:\tR (running)\nTgid:\t47735\nNgid:\t0\nPid:\t47735\nPPid:\t47620\nTracerPid:\t47620\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nFDSize:\t64\nGroups:\t4 20 24 25 27 29 30 44 46 100 106 111 11"...)
R9 : 0x410 
R10: 0x1000 
R11: 0x246 
R12: 0x0 
R13: 0x7fffffffde58 --> 0x7fffffffe203 ("LESS_TERMCAP_se=\033[0m")
R14: 0x555555820dc8 --> 0x555555555220 (<__do_global_dtors_aux>:        endbr64)
R15: 0x7ffff7ffd000 --> 0x7ffff7ffe2d0 --> 0x555555554000 --> 0x10102464c457f
EFLAGS: 0x206 (carry PARITY adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x5555557ee936 <main+228>:   mov    esi,0x100
   0x5555557ee93b <main+233>:   mov    rdi,rax
   0x5555557ee93e <main+236>:   call   0x555555555130 <fgets@plt>
=> 0x5555557ee943 <main+241>:   test   rax,rax
   0x5555557ee946 <main+244>:   jne    0x5555557ee8bf <main+109>
   0x5555557ee94c <main+250>:   mov    rax,QWORD PTR [rbp-0x10]
   0x5555557ee950 <main+254>:   mov    rdi,rax
   0x5555557ee953 <main+257>:   call   0x5555555550c0 <fclose@plt>
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdbb0 --> 0x7fffffffde48 --> 0x7fffffffe1b9 ("/home/kali/Downloads/challenges/CSC/writeups/reverse/possible_writer/main")
0008| 0x7fffffffdbb8 --> 0x14d524554 
0016| 0x7fffffffdbc0 --> 0x0 
0024| 0x7fffffffdbc8 --> 0x0 
0032| 0x7fffffffdbd0 --> 0x0 
0040| 0x7fffffffdbd8 --> 0x0 
0048| 0x7fffffffdbe0 --> 0x0 
0056| 0x7fffffffdbe8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x00005555557ee943 in main ()
gdb-peda$ set $rax = 0
gdb-peda$ disas main
```

here we can set the rax register value to 0 to bypass the anti debugger then we disas the main to figure out where is the random number being stored to we can change it to ```845```

```c
gdb-peda$ disas main
Dump of assembler code for function main:
   0x00005555557ee852 <+0>:     push   rbp
   0x00005555557ee853 <+1>:     mov    rbp,rsp
   0x00005555557ee856 <+4>:     sub    rsp,0x180
   0x00005555557ee85d <+11>:    mov    DWORD PTR [rbp-0x174],edi
   0x00005555557ee863 <+17>:    mov    QWORD PTR [rbp-0x180],rsi
   0x00005555557ee86a <+24>:    lea    rax,[rip+0x7ce]        # 0x5555557ef03f
   0x00005555557ee871 <+31>:    mov    rsi,rax
   0x00005555557ee874 <+34>:    lea    rax,[rip+0x882]        # 0x5555557ef0fd
   0x00005555557ee87b <+41>:    mov    rdi,rax
   0x00005555557ee87e <+44>:    call   0x5555555550e0 <fopen@plt>
   0x00005555557ee883 <+49>:    mov    QWORD PTR [rbp-0x10],rax
   0x00005555557ee887 <+53>:    cmp    QWORD PTR [rbp-0x10],0x0
   0x00005555557ee88c <+58>:    jne    0x5555557ee92b <main+217>
   0x00005555557ee892 <+64>:    mov    rax,QWORD PTR [rip+0x32827]        # 0x5555558210c0 <stderr@GLIBC_2.2.5>
   0x00005555557ee899 <+71>:    mov    rcx,rax
   0x00005555557ee89c <+74>:    mov    edx,0x1b
   0x00005555557ee8a1 <+79>:    mov    esi,0x1
   0x00005555557ee8a6 <+84>:    lea    rax,[rip+0x862]        # 0x5555557ef10f
   0x00005555557ee8ad <+91>:    mov    rdi,rax
   0x00005555557ee8b0 <+94>:    call   0x555555555150 <fwrite@plt>
   0x00005555557ee8b5 <+99>:    mov    eax,0x1
   0x00005555557ee8ba <+104>:   jmp    0x5555557eea99 <main+583>
   0x00005555557ee8bf <+109>:   lea    rax,[rbp-0x120]
   0x00005555557ee8c6 <+116>:   mov    edx,0x9
   0x00005555557ee8cb <+121>:   lea    rcx,[rip+0x859]        # 0x5555557ef12b
   0x00005555557ee8d2 <+128>:   mov    rsi,rcx
   0x00005555557ee8d5 <+131>:   mov    rdi,rax
   0x00005555557ee8d8 <+134>:   call   0x555555555060 <strncmp@plt>
   0x00005555557ee8dd <+139>:   test   eax,eax
   0x00005555557ee8df <+141>:   jne    0x5555557ee92b <main+217>
   0x00005555557ee8e1 <+143>:   lea    rdx,[rbp-0x164]
   0x00005555557ee8e8 <+150>:   lea    rax,[rbp-0x120]
   0x00005555557ee8ef <+157>:   lea    rcx,[rip+0x83f]        # 0x5555557ef135
   0x00005555557ee8f6 <+164>:   mov    rsi,rcx
   0x00005555557ee8f9 <+167>:   mov    rdi,rax
   0x00005555557ee8fc <+170>:   mov    eax,0x0
   0x00005555557ee901 <+175>:   call   0x5555555550b0 <__isoc99_sscanf@plt>
   0x00005555557ee906 <+180>:   cmp    eax,0x1
   0x00005555557ee909 <+183>:   jne    0x5555557ee92b <main+217>
   0x00005555557ee90b <+185>:   mov    eax,DWORD PTR [rbp-0x164]
   0x00005555557ee911 <+191>:   test   eax,eax
   0x00005555557ee913 <+193>:   je     0x5555557ee92b <main+217>
   0x00005555557ee915 <+195>:   mov    rax,QWORD PTR [rbp-0x10]
   0x00005555557ee919 <+199>:   mov    rdi,rax
   0x00005555557ee91c <+202>:   call   0x5555555550c0 <fclose@plt>
   0x00005555557ee921 <+207>:   mov    eax,0x0
   0x00005555557ee926 <+212>:   jmp    0x5555557eea99 <main+583>
   0x00005555557ee92b <+217>:   mov    rdx,QWORD PTR [rbp-0x10]
   0x00005555557ee92f <+221>:   lea    rax,[rbp-0x120]
   0x00005555557ee936 <+228>:   mov    esi,0x100
   0x00005555557ee93b <+233>:   mov    rdi,rax
   0x00005555557ee93e <+236>:   call   0x555555555130 <fgets@plt>
=> 0x00005555557ee943 <+241>:   test   rax,rax
   0x00005555557ee946 <+244>:   jne    0x5555557ee8bf <main+109>
   0x00005555557ee94c <+250>:   mov    rax,QWORD PTR [rbp-0x10]
   0x00005555557ee950 <+254>:   mov    rdi,rax
   0x00005555557ee953 <+257>:   call   0x5555555550c0 <fclose@plt>
   0x00005555557ee958 <+262>:   mov    edi,0x0
   0x00005555557ee95d <+267>:   call   0x555555555090 <time@plt>
   0x00005555557ee962 <+272>:   mov    edi,eax
   0x00005555557ee964 <+274>:   call   0x5555555550a0 <srand@plt>
   0x00005555557ee969 <+279>:   call   0x555555555040 <rand@plt>
   0x00005555557ee96e <+284>:   movsxd rdx,eax
   0x00005555557ee971 <+287>:   imul   rdx,rdx,0x34f3fa1b
   0x00005555557ee978 <+294>:   shr    rdx,0x20
   0x00005555557ee97c <+298>:   sar    edx,0xb
   0x00005555557ee97f <+301>:   mov    ecx,eax
   0x00005555557ee981 <+303>:   sar    ecx,0x1f
   0x00005555557ee984 <+306>:   sub    edx,ecx
   0x00005555557ee986 <+308>:   imul   ecx,edx,0x26ad
   0x00005555557ee98c <+314>:   sub    eax,ecx
   0x00005555557ee98e <+316>:   mov    edx,eax
   0x00005555557ee990 <+318>:   lea    eax,[rdx+0x2710]
   0x00005555557ee996 <+324>:   mov    DWORD PTR [rbp-0x14],eax
   0x00005555557ee999 <+327>:   mov    edx,DWORD PTR [rbp-0x14]
   0x00005555557ee99c <+330>:   lea    rax,[rbp-0x140]
   0x00005555557ee9a3 <+337>:   mov    rsi,rax
   0x00005555557ee9a6 <+340>:   lea    rax,[rip+0x65b]        # 0x5555557ef008
   0x00005555557ee9ad <+347>:   mov    rdi,rax
   0x00005555557ee9b0 <+350>:   call   0x5555557ee68b <FUN_00101269>
   0x00005555557ee9b5 <+355>:   lea    rax,[rip+0x78c]        # 0x5555557ef148
   0x00005555557ee9bc <+362>:   mov    rdi,rax
   0x00005555557ee9bf <+365>:   mov    eax,0x0
   0x00005555557ee9c4 <+370>:   call   0x555555555030 <printf@plt>
   0x00005555557ee9c9 <+375>:   mov    DWORD PTR [rbp-0x4],0x0
   0x00005555557ee9d0 <+382>:   jmp    0x5555557ee9fc <main+426>
   0x00005555557ee9d2 <+384>:   lea    rdx,[rbp-0x160]
   0x00005555557ee9d9 <+391>:   mov    eax,DWORD PTR [rbp-0x4]
   0x00005555557ee9dc <+394>:   cdqe
   0x00005555557ee9de <+396>:   add    rax,rdx
   0x00005555557ee9e1 <+399>:   mov    rsi,rax
   0x00005555557ee9e4 <+402>:   lea    rax,[rip+0x782]        # 0x5555557ef16d
   0x00005555557ee9eb <+409>:   mov    rdi,rax
   0x00005555557ee9ee <+412>:   mov    eax,0x0
   0x00005555557ee9f3 <+417>:   call   0x5555555550d0 <__isoc99_scanf@plt>
   0x00005555557ee9f8 <+422>:   add    DWORD PTR [rbp-0x4],0x1
   0x00005555557ee9fc <+426>:   cmp    DWORD PTR [rbp-0x4],0x1f
   0x00005555557eea00 <+430>:   jle    0x5555557ee9d2 <main+384>
   0x00005555557eea02 <+432>:   lea    rax,[rip+0x76a]        # 0x5555557ef173
   0x00005555557eea09 <+439>:   mov    rdi,rax
   0x00005555557eea0c <+442>:   mov    eax,0x0
   0x00005555557eea11 <+447>:   call   0x555555555030 <printf@plt>
   0x00005555557eea16 <+452>:   mov    DWORD PTR [rbp-0x8],0x0
   0x00005555557eea1d <+459>:   jmp    0x5555557eea49 <main+503>
   0x00005555557eea1f <+461>:   mov    eax,DWORD PTR [rbp-0x8]
   0x00005555557eea22 <+464>:   cdqe
   0x00005555557eea24 <+466>:   movzx  eax,BYTE PTR [rbp+rax*1-0x160]
   0x00005555557eea2c <+474>:   movzx  eax,al
   0x00005555557eea2f <+477>:   mov    esi,eax
   0x00005555557eea31 <+479>:   lea    rax,[rip+0x74a]        # 0x5555557ef182
   0x00005555557eea38 <+486>:   mov    rdi,rax
   0x00005555557eea3b <+489>:   mov    eax,0x0
   0x00005555557eea40 <+494>:   call   0x555555555030 <printf@plt>
   0x00005555557eea45 <+499>:   add    DWORD PTR [rbp-0x8],0x1
   0x00005555557eea49 <+503>:   cmp    DWORD PTR [rbp-0x8],0x1f
   0x00005555557eea4d <+507>:   jle    0x5555557eea1f <main+461>
   0x00005555557eea4f <+509>:   mov    edi,0xa
   0x00005555557eea54 <+514>:   call   0x555555555100 <putchar@plt>
   0x00005555557eea59 <+519>:   lea    rcx,[rbp-0x160]
   0x00005555557eea60 <+526>:   lea    rax,[rbp-0x140]
   0x00005555557eea67 <+533>:   mov    edx,0x20
   0x00005555557eea6c <+538>:   mov    rsi,rcx
   0x00005555557eea6f <+541>:   mov    rdi,rax
   0x00005555557eea72 <+544>:   call   0x555555555050 <memcmp@plt>
   0x00005555557eea77 <+549>:   mov    DWORD PTR [rbp-0x18],eax
   0x00005555557eea7a <+552>:   cmp    DWORD PTR [rbp-0x18],0x0
   0x00005555557eea7e <+556>:   jne    0x5555557eea94 <main+578>
   0x00005555557eea80 <+558>:   mov    edx,DWORD PTR [rbp-0x14]
   0x00005555557eea83 <+561>:   lea    rax,[rbp-0x140]
   0x00005555557eea8a <+568>:   mov    esi,edx
   0x00005555557eea8c <+570>:   mov    rdi,rax
   0x00005555557eea8f <+573>:   call   0x5555557ee46a <Fun_1>
   0x00005555557eea94 <+578>:   mov    eax,0x0
   0x00005555557eea99 <+583>:   leave
   0x00005555557eea9a <+584>:   ret
End of assembler dump.
gdb-peda$ b *0x00005555557ee996
Breakpoint 3 at 0x5555557ee996
gdb-peda$ c
```

we can see that the random number is being stored at address 0x00005555557ee996 so we set a breakpoint there to change it

```c
[----------------------------------registers-----------------------------------]
RAX: 0x3e2a ('*>')
RBX: 0x7fffffffde48 --> 0x7fffffffe1b9 ("/home/kali/Downloads/challenges/CSC/writeups/reverse/possible_writer/main")
RCX: 0x2faf0b20 
RDX: 0x171a 
RSI: 0x7fffffffdb84 --> 0x332c2c002faf223a 
RDI: 0x7ffff79f1860 --> 0x7ffff79f1214 --> 0xa7233f652d8f91d1 
RBP: 0x7fffffffdd30 --> 0x1 
RSP: 0x7fffffffdbb0 --> 0x7fffffffde48 --> 0x7fffffffe1b9 ("/home/kali/Downloads/challenges/CSC/writeups/reverse/possible_writer/main")
RIP: 0x5555557ee996 (<main+324>:        mov    DWORD PTR [rbp-0x14],eax)
R8 : 0x7ffff79f1214 --> 0xa7233f652d8f91d1 
R9 : 0x7ffff79f1280 --> 0x8 
R10: 0x7ffff782f968 --> 0x100012000027b8 
R11: 0x7ffff785eb10 (<rand>:    sub    rsp,0x8)
R12: 0x0 
R13: 0x7fffffffde58 --> 0x7fffffffe203 ("LESS_TERMCAP_se=\033[0m")
R14: 0x555555820dc8 --> 0x555555555220 (<__do_global_dtors_aux>:        endbr64)
R15: 0x7ffff7ffd000 --> 0x7ffff7ffe2d0 --> 0x555555554000 --> 0x10102464c457f
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x5555557ee98c <main+314>:   sub    eax,ecx
   0x5555557ee98e <main+316>:   mov    edx,eax
   0x5555557ee990 <main+318>:   lea    eax,[rdx+0x2710]
=> 0x5555557ee996 <main+324>:   mov    DWORD PTR [rbp-0x14],eax
   0x5555557ee999 <main+327>:   mov    edx,DWORD PTR [rbp-0x14]
   0x5555557ee99c <main+330>:   lea    rax,[rbp-0x140]
   0x5555557ee9a3 <main+337>:   mov    rsi,rax
   0x5555557ee9a6 <main+340>:   lea    rax,[rip+0x65b]        # 0x5555557ef008
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdbb0 --> 0x7fffffffde48 --> 0x7fffffffe1b9 ("/home/kali/Downloads/challenges/CSC/writeups/reverse/possible_writer/main")
0008| 0x7fffffffdbb8 --> 0x14d524554 
0016| 0x7fffffffdbc0 --> 0x0 
0024| 0x7fffffffdbc8 --> 0x0 
0032| 0x7fffffffdbd0 --> 0x0 
0040| 0x7fffffffdbd8 --> 0x0 
0048| 0x7fffffffdbe0 --> 0x0 
0056| 0x7fffffffdbe8 --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 3, 0x00005555557ee996 in main ()
gdb-peda$ set $rax = 845
```

that should be it now we can continue the program and enter the hash that we already have

```c
gdb-peda$ c
Continuing.
[Detaching after vfork from child process 51770]
[Detaching after vfork from child process 51773]
Enter hash (in hexadecimal format): d9317ef25cedec862039b257cd83b1b536d3ae272ec4b2dde9b9d05e8169455a
Entered hash: d9317ef25cedec862039b257cd83b1b536d3ae272ec4b2dde9b9d05e8169455a
CSCCTF{1_L1k3_Y0ur_Sk1ll_1ssu3s}
```

FLAG: ```CSCCTF{1_L1k3_Y0ur_Sk1ll_1ssu3s}```