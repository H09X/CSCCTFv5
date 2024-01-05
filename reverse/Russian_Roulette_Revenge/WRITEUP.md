## Challenge - Russian Roulette Revenge [Rev]

### Description

```
This time i will win
```

---

### Reversing the Binary 

#### Analyzing Main

Below we can see the decompiled ```main``` function. 

```c

undefined8 main(undefined8 param_1,char **param_2)

{
  int iVar1;
  time_t tVar2;
  char local_3d;
  int local_3c;
  undefined local_38 [40];
  int local_10;
  uint local_c;
  
  calc_hash(*param_2,local_38);
  iVar1 = memcmp(local_38,&stored_hash,0x20);
  if (iVar1 != 0) {
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  tVar2 = time((time_t *)0x0);
  srand((uint)tVar2);
  local_10 = rand();
  puts(
      "Are you ready to test your luck and nerve? Join me in a game of Russian Roulette and let fate  decide who prevails! Accept the challenge if you dare.\n [y] for yes, [n] for no."
      );
  __isoc99_scanf(&DAT_00102127,&local_3d);
  if (local_3d == 'y') {
    printf(
          "well well well, we got ourself a little gambler\nfine you go first\nTake a shot if you da re: "
          );
    __isoc99_scanf(&DAT_0010218c,&local_3c);
    if (local_10 == local_3c) {
      puts("I Quit\nHere you can have your stupid prize.");
      Fun_1();
    }
    else {
      system("clear");
      for (local_c = 0x1ea; (int)local_c < 0x28a; local_c = local_c + 1) {
        printf("            ,___________________________________________/7_ \n           |-_______-- ----. `\\                             |%*s\n"
               ,(ulong)local_c,
               "o\n       _,/ | _______)     |___\\____________________________|\n  .__/`((  | _____ __      | (/))_______________=.\n     `~) \\ | _______)     |   /----------------_/\n        `__y|______________|  /\n       / ________ __________/\n      / /#####\\(  \\  /     ))\n     / /#######|\\  \\(     //\n    / /########|.\\______ad/`\n   / /###(\ \)###||`------``\n  / /##########||\n / /###########||\n( (############||\n \\ \\#### (/)####))\n  \\ \\#########//\n   \\ \\#######//\n    `---|_|--`\n       ((_))\n        `-`\n"
              );
        usleep(10000);
        system("clear");
      }
      puts(
          "            ,___________________________________________/7_ \n           |-_______------.  `\\                             |\n       _,/ | _______)     |___\\______________________ ______|\n  .__/`((  | _______      | (/))_______________=.\n     `~) \\ | _______)     |   /----------------_/\n       `__y|______________|  /\n       / ________ __________/\n      / /#####\\(  \\  /     ))\n     / /#######|\\  \\(     //\n    / /########|.\\______ad/`\ n   / /###(\\)###||`------``\n  / /##########||\n / /###########||\n( (############||\n \\  \\####(/)####))\n  \\ \\#########//\n   \\ \\#######//\n    `---|_|--`\n       ((_))\n        `-`"
          );
      printf("\nYou Died.");
      remove(*param_2);
    }
  }
  else {
    puts("Playing it safe huh?");
  }
  return 0;
}

```

**Analysis:** This code seems to generate a random number and asks the user to input a number if both numbers are the same a prize will be printed which most likely will be the flag.
Trying to patch the if statment didnt work do to the calc_hash function that finds the hash of the main and compares it to a hard coded hash if the hashes dont match the program will exit.
Instead of trying to find a way around this anti-patching technique i decieded to fire up gdb.

---

### Solution

**Dynamic Analysis:** first thing i do is to set a breakpoint at the main then i run the program

```c
┌──(kali㉿M0tH3r5h1P)-[~/…/CSC/writeups/reverse/Russian_Roulette_Revenge]
└─$ gdb-peda revenge 
Reading symbols from revenge...
(No debugging symbols found in revenge)
gdb-peda$ b main
Breakpoint 1 at 0x1a80
gdb-peda$ r
```

Then i disassemble the main and find where is the random number being stored and set a breakpoint there

```c
gdb-peda$ disas main
Dump of assembler code for function main:
   0x0000555555555a7c <+0>:     push   rbp
   0x0000555555555a7d <+1>:     mov    rbp,rsp
=> 0x0000555555555a80 <+4>:     sub    rsp,0x50
   0x0000555555555a84 <+8>:     mov    DWORD PTR [rbp-0x44],edi
   0x0000555555555a87 <+11>:    mov    QWORD PTR [rbp-0x50],rsi
   0x0000555555555a8b <+15>:    mov    rax,QWORD PTR [rbp-0x50]
   0x0000555555555a8f <+19>:    mov    rax,QWORD PTR [rax]
   0x0000555555555a92 <+22>:    lea    rdx,[rbp-0x30]
   0x0000555555555a96 <+26>:    mov    rsi,rdx
   0x0000555555555a99 <+29>:    mov    rdi,rax
   0x0000555555555a9c <+32>:    call   0x555555555249 <calc_hash>
   0x0000555555555aa1 <+37>:    lea    rax,[rbp-0x30]
   0x0000555555555aa5 <+41>:    mov    edx,0x20
   0x0000555555555aaa <+46>:    lea    rcx,[rip+0x56f]        # 0x555555556020 <stored_hash>
   0x0000555555555ab1 <+53>:    mov    rsi,rcx
   0x0000555555555ab4 <+56>:    mov    rdi,rax
   0x0000555555555ab7 <+59>:    call   0x5555555550f0 <memcmp@plt>
   0x0000555555555abc <+64>:    test   eax,eax
   0x0000555555555abe <+66>:    je     0x555555555aca <main+78>
   0x0000555555555ac0 <+68>:    mov    edi,0x1
   0x0000555555555ac5 <+73>:    call   0x555555555070 <exit@plt>
   0x0000555555555aca <+78>:    mov    edi,0x0
   0x0000555555555acf <+83>:    call   0x555555555140 <time@plt>
   0x0000555555555ad4 <+88>:    mov    edi,eax
   0x0000555555555ad6 <+90>:    call   0x5555555550d0 <srand@plt>
   0x0000555555555adb <+95>:    call   0x555555555120 <rand@plt>
   0x0000555555555ae0 <+100>:   mov    DWORD PTR [rbp-0x8],eax
   0x0000555555555ae3 <+103>:   lea    rax,[rip+0x58e]        # 0x555555556078
   0x0000555555555aea <+110>:   mov    rdi,rax
   0x0000555555555aed <+113>:   call   0x555555555060 <puts@plt>
   0x0000555555555af2 <+118>:   lea    rax,[rbp-0x35]
   0x0000555555555af6 <+122>:   mov    rsi,rax
   0x0000555555555af9 <+125>:   lea    rax,[rip+0x627]        # 0x555555556127
   0x0000555555555b00 <+132>:   mov    rdi,rax
   0x0000555555555b03 <+135>:   mov    eax,0x0
   0x0000555555555b08 <+140>:   call   0x5555555550e0 <__isoc99_scanf@plt>
   0x0000555555555b0d <+145>:   movzx  eax,BYTE PTR [rbp-0x35]
   0x0000555555555b11 <+149>:   cmp    al,0x79
   0x0000555555555b13 <+151>:   jne    0x555555555c01 <main+389>
   0x0000555555555b19 <+157>:   lea    rax,[rip+0x610]        # 0x555555556130
   0x0000555555555b20 <+164>:   mov    rdi,rax
   0x0000555555555b23 <+167>:   mov    eax,0x0
   0x0000555555555b28 <+172>:   call   0x555555555030 <printf@plt>
   0x0000555555555b2d <+177>:   lea    rax,[rbp-0x34]
   0x0000555555555b31 <+181>:   mov    rsi,rax
   0x0000555555555b34 <+184>:   lea    rax,[rip+0x651]        # 0x55555555618c
   0x0000555555555b3b <+191>:   mov    rdi,rax
   0x0000555555555b3e <+194>:   mov    eax,0x0
   0x0000555555555b43 <+199>:   call   0x5555555550e0 <__isoc99_scanf@plt>
   0x0000555555555b48 <+204>:   mov    eax,DWORD PTR [rbp-0x34]
   0x0000555555555b4b <+207>:   cmp    DWORD PTR [rbp-0x8],eax
   0x0000555555555b4e <+210>:   je     0x555555555be6 <main+362>
   0x0000555555555b54 <+216>:   lea    rax,[rip+0x634]        # 0x55555555618f
   0x0000555555555b5b <+223>:   mov    rdi,rax
   0x0000555555555b5e <+226>:   call   0x555555555090 <system@plt>
   0x0000555555555b63 <+231>:   mov    DWORD PTR [rbp-0x4],0x1ea
   0x0000555555555b6a <+238>:   jmp    0x555555555ba9 <main+301>
   0x0000555555555b6c <+240>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000555555555b6f <+243>:   lea    rdx,[rip+0x622]        # 0x555555556198
   0x0000555555555b76 <+250>:   mov    esi,eax
   0x0000555555555b78 <+252>:   lea    rax,[rip+0x801]        # 0x555555556380
   0x0000555555555b7f <+259>:   mov    rdi,rax
   0x0000555555555b82 <+262>:   mov    eax,0x0
   0x0000555555555b87 <+267>:   call   0x555555555030 <printf@plt>
   0x0000555555555b8c <+272>:   mov    edi,0x2710
   0x0000555555555b91 <+277>:   call   0x5555555550b0 <usleep@plt>
   0x0000555555555b96 <+282>:   lea    rax,[rip+0x5f2]        # 0x55555555618f
   0x0000555555555b9d <+289>:   mov    rdi,rax
   0x0000555555555ba0 <+292>:   call   0x555555555090 <system@plt>
   0x0000555555555ba5 <+297>:   add    DWORD PTR [rbp-0x4],0x1
   0x0000555555555ba9 <+301>:   cmp    DWORD PTR [rbp-0x4],0x289
   0x0000555555555bb0 <+308>:   jle    0x555555555b6c <main+240>
   0x0000555555555bb2 <+310>:   lea    rax,[rip+0x847]        # 0x555555556400
   0x0000555555555bb9 <+317>:   mov    rdi,rax
   0x0000555555555bbc <+320>:   call   0x555555555060 <puts@plt>
   0x0000555555555bc1 <+325>:   lea    rax,[rip+0xa94]        # 0x55555555665c
   0x0000555555555bc8 <+332>:   mov    rdi,rax
   0x0000555555555bcb <+335>:   mov    eax,0x0
   0x0000555555555bd0 <+340>:   call   0x555555555030 <printf@plt>
   0x0000555555555bd5 <+345>:   mov    rax,QWORD PTR [rbp-0x50]
   0x0000555555555bd9 <+349>:   mov    rax,QWORD PTR [rax]
   0x0000555555555bdc <+352>:   mov    rdi,rax
   0x0000555555555bdf <+355>:   call   0x555555555110 <remove@plt>
   0x0000555555555be4 <+360>:   jmp    0x555555555c10 <main+404>
   0x0000555555555be6 <+362>:   lea    rax,[rip+0xa7b]        # 0x555555556668
   0x0000555555555bed <+369>:   mov    rdi,rax
   0x0000555555555bf0 <+372>:   call   0x555555555060 <puts@plt>
   0x0000555555555bf5 <+377>:   mov    eax,0x0
   0x0000555555555bfa <+382>:   call   0x555555555a6b <Fun_1>
   0x0000555555555bff <+387>:   jmp    0x555555555c10 <main+404>
   0x0000555555555c01 <+389>:   lea    rax,[rip+0xa8c]        # 0x555555556694
   0x0000555555555c08 <+396>:   mov    rdi,rax
   0x0000555555555c0b <+399>:   call   0x555555555060 <puts@plt>
   0x0000555555555c10 <+404>:   mov    eax,0x0
   0x0000555555555c15 <+409>:   leave
   0x0000555555555c16 <+410>:   ret
End of assembler dump.
gdb-peda$
```

As we can see the random number is being stored t=at the rax register at address ```0x0000555555555ae0``` so i set a breakpoint there then continue the program

```c
gdb-peda$ b *0x0000555555555ae0
Breakpoint 2 at 0x555555555ae0
gdb-peda$ c
Continuing.
[Attaching after Thread 0x7ffff7fa2740 (LWP 13479) vfork to child process 14852]
[New inferior 2 (process 14852)]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Detaching vfork parent process 13479 after child exec]
[Inferior 1 (process 13479) detached]
process 14852 is executing new program: /usr/bin/dash
Error in re-setting breakpoint 1: Function "main" not defined.
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Attaching after Thread 0x7ffff7dc0740 (LWP 14852) fork to child process 14853]
[New inferior 3 (process 14853)]
[Detaching after fork from parent process 14852]
[Inferior 2 (process 14852) detached]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
process 14853 is executing new program: /usr/bin/x86_64-linux-gnu-objdump
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Inferior 3 (process 14853) exited normally]
Are you ready to test your luck and nerve? Join me in a game of Russian Roulette and let fate decide who prevails! Accept the challenge if you dare.
 [y] for yes, [n] for no.
Warning: not running
gdb-peda$ 
```

This caused an error due to a child proccess being debugged so i set the follow-fork-mode to parent (child by default in peda and pwndbg and parent in gif) and redo the steps above

```
┌──(kali㉿M0tH3r5h1P)-[~/…/CSC/writeups/reverse/Russian_Roulette_Revenge]
└─$ gdb-peda revenge
Reading symbols from revenge...
(No debugging symbols found in revenge)
gdb-peda$ set follow-fork-mode parent
```

Doing the steps again gets us this output 

```c
[----------------------------------registers-----------------------------------]
RAX: 0xb702ac7 
RBX: 0x7fffffffde18 --> 0x7fffffffe183 ("/home/kali/Downloads/challenges/CSC/writeups/reverse/Russian_Roulette_Revenge/revenge")
RCX: 0x7ffff79f1208 --> 0x6f32723dcb20f5a1 
RDX: 0x0 
RSI: 0x7fffffffdc84 --> 0xf85de1000b702ac7 
RDI: 0x7ffff79f1860 --> 0x7ffff79f1214 --> 0xe8f1d4efa069259e 
RBP: 0x7fffffffdd00 --> 0x1 
RSP: 0x7fffffffdcb0 --> 0x7fffffffde18 --> 0x7fffffffe183 ("/home/kali/Downloads/challenges/CSC/writeups/reverse/Russian_Roulette_Revenge/revenge")
RIP: 0x555555555ae0 (<main+100>:        mov    DWORD PTR [rbp-0x8],eax)
R8 : 0x7ffff79f1214 --> 0xe8f1d4efa069259e 
R9 : 0x7ffff79f1280 --> 0x8 
R10: 0x7ffff782f968 --> 0x100012000027b8 
R11: 0x7ffff785eb10 (<rand>:    sub    rsp,0x8)
R12: 0x0 
R13: 0x7fffffffde28 --> 0x7fffffffe1d9 ("LESS_TERMCAP_se=\033[0m")
R14: 0x555555558dc8 --> 0x555555555200 (<__do_global_dtors_aux>:        endbr64)
R15: 0x7ffff7ffd000 --> 0x7ffff7ffe2d0 --> 0x555555554000 --> 0x10102464c457f
EFLAGS: 0x202 (carry parity adjust zero sign trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x555555555ad4 <main+88>:    mov    edi,eax
   0x555555555ad6 <main+90>:    call   0x5555555550d0 <srand@plt>
   0x555555555adb <main+95>:    call   0x555555555120 <rand@plt>
=> 0x555555555ae0 <main+100>:   mov    DWORD PTR [rbp-0x8],eax
   0x555555555ae3 <main+103>:   lea    rax,[rip+0x58e]        # 0x555555556078
   0x555555555aea <main+110>:   mov    rdi,rax
   0x555555555aed <main+113>:   call   0x555555555060 <puts@plt>
   0x555555555af2 <main+118>:   lea    rax,[rbp-0x35]
[------------------------------------stack-------------------------------------]
0000| 0x7fffffffdcb0 --> 0x7fffffffde18 --> 0x7fffffffe183 ("/home/kali/Downloads/challenges/CSC/writeups/reverse/Russian_Roulette_Revenge/revenge")
0008| 0x7fffffffdcb8 --> 0x100000000 
0016| 0x7fffffffdcc0 --> 0x0 
0024| 0x7fffffffdcc8 --> 0x0 
0032| 0x7fffffffdcd0 --> 0x242222c69b129c91 
0040| 0x7fffffffdcd8 --> 0x6039cdc14d6e2ab7 
0048| 0x7fffffffdce0 --> 0x44ee18a1b0da414d 
0056| 0x7fffffffdce8 --> 0x20a5ea1e8a5416b0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value

Breakpoint 2, 0x0000555555555ae0 in main ()
gdb-peda$ c
```

So we take the rax register value ```0xb702ac7``` (191900359 decimal) then continue the program and enter it 

```c
gdb-peda$ c
Continuing.
Are you ready to test your luck and nerve? Join me in a game of Russian Roulette and let fate decide who prevails! Accept the challenge if you dare.
 [y] for yes, [n] for no.
y
well well well, we got ourself a little gambler
fine you go first
Take a shot if you dare: 191900359
I Quit
Here you can have your stupid prize.
CSCCTF{Chamber_Of_Risky_Bytes}[Inferior 1 (process 18238) exited with code 01]
Warning: not running
gdb-peda$
```

flag: ```CSCCTF{Chamber_Of_Risky_Bytes}```

