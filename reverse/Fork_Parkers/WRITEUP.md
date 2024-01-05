## Challenge - Fork Parker's [Rev]

### Description

```
May the fork be with you

wrap the last val being passed to function H04X in CSCCTF{}
```

---

### Reversing the Binary 

#### Analyzing Main

Below we can see the decompiled ```main``` function. 

```c
undefined8 main(void)

{
  int *piVar1;
  
  piVar1 = (int *)mmap((void *)0x0,4,3,0x22,-1,0);
  *piVar1 = 0x5036bfa7;
  fork();
  fork();
  fork();
  fork();
  *piVar1 = *piVar1 + 0x99602d2;
  H04X(*piVar1);
  return 0;
}

```

**Analysis:** The initial value assigned to *piVar1 is 1345765287. After performing fork() four times, the code increments the value at piVar1 by 0x99602d2 in each of the processes created.

In this case, there are 16 total processes created due to the four successive fork() calls. Each process will increment the value by 0x99602d2. Hence, the correct calculation of the final value at *piVar1 would indeed be:

1345765287 + (16* 0x99602d2)

This sum exceeds the maximum limit for a signed 32-bit integer. When this happens, the value wraps around within the range of a signed integer, resulting in the final value being: -375984953

---


the flag: ```CSCCTF{-375984953}```





