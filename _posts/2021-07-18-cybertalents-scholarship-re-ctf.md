---
title: CyberTalents Scholarship - Reverse Engineering CTF
date: 2021-07-19 22:22:00 +0200
categories: [CTF, Writeups]
tags: ctf writeups reverse reverse-engineering assembly idapro python crypto unpacking obfuscation
image: /assets/img/posts/2021-07-18-cybertalents-scholarship-re-ctf/cover.png
---
{% assign img_root = "/assets/img/posts/2021-07-18-cybertalents-scholarship-re-ctf" %}

This was my first CTF to get the <span style="color:#feca57;">**1<sup>st</sup> place**</span> ever and my first <span style="color:#ff6b6b;">**first-blood**</span> for the hard challenge!! The CTF was after finishing the first course in the Cybertalents scholarship sponsored by Trend Micro which was about Reverse Engineering, I really enjoyed the course and I learned a lot from the instructor [joezid](https://joezid.github.io/){:target="_blank"} throughout the 6 sessions from very basic topics like the malware analysis lab setup till advanced topics like unpacking!

<img src="{{img_root}}/scoreboard.png" alt="scoreboard">

<hr>

## list

<img src="{{img_root}}/info/list.png" alt="list">
Flag: `blacklist`

<hr>

## r0t4t0r

<img src="{{img_root}}/info/rotator.png" alt="r0t4t0r">

By viewing the strings on PEstudio I notices these interesting strings:

<img src="{{img_root}}/challenges/rotator/1.png" alt="PEstudio's strings">

So I assumed from this that I need to enter a string then it will be encrypted and compared to the encrypted flag as a whole or as letters!

By using IDApro to look at the code:

<img src="{{img_root}}/challenges/rotator/2.png" alt="IDApro main function">

My assumption was correct it basically takes the user input and encrypts each character and compare it to hard coded encrypted character, now I need to:
- Get that hard coded values
- Understand the encryption to build the decryption logic

To get the hard coded values I stepped over the MOVs instructions at the start of the main function and got them at the memory address `[rbp+10h+var_50]`:

<img src="{{img_root}}/challenges/rotator/3.png" alt="hard coded values">


Then I went for the encryption function:
<img src="{{img_root}}/challenges/rotator/4.png" alt="encryption function">

After checking the parameters values I rewrote this as:

`(letter >> ((8 - 2) & 7)) | (letter << 2)` = `(letter >> 6) | (letter << 2)`

And that has two solutions:
- Bruteforcing the printable letters and encrypt them with the same algorithm and match with the hard coded letter
- This is actually rotate left, so I can rotate right the encrypted values to get the flag

And this is the python script for both solutions:

```python
from string import printable
hardcoded = [0x99, 0xB1, 0x85, 0x9D, 0xED, 0xCC, 0xD0, 0xCD, 0xE5, 0x7D, 0xC9, 0xC0, 0xD1, 0xD0, 0xD1, 0xCC, 0x7D, 0x31, 0xCC, 0x99, 0xD1, 0x7D, 0xD0, 0xCD, 0x7D, 0xC4, 0xC8, 0xCC, 0xD0, 0xF5]

flag = ""

# solution 1: bruteforce
for h in hardcoded:
    for x in printable:
        if ((ord(x)>>6) | (ord(x) << 2)) & 0xff == h:
            flag += x

print(flag)

# solutions 2: rotate right
flag = ""

for h in hardcoded:
    flag += chr(((h << 6) | (h >> 2)) & 0xff)

print(flag)
```

Flag: `flag{34sy_r0t4t3_L3ft_4s_1234}`

<hr>

## Assembly Master

<img src="{{img_root}}/info/assembly_master.png" alt="Assembly Master">

Given an assembly code:
```java
x:
        .ascii  "v\200suizgahMsMa{\177d\200wMl}bMq|s\200\200w~uwo"
.LC0:
        .string "Wrong flag "
.LC1:
        .string "correct flag :D "
Secret_Checker:
        push    rbp
        mov     rbp, rsp
        sub     rsp, 32
        mov     QWORD PTR [rbp-24], rdi
        mov     DWORD PTR [rbp-4], 0
        jmp     .L2
.L5:
        mov     eax, DWORD PTR [rbp-4]
        movsx   rdx, eax
        mov     rax, QWORD PTR [rbp-24]
        add     rax, rdx
        movzx   eax, BYTE PTR [rax]
        xor     eax, 19
        movsx   eax, al
        lea     edx, [rax+1]
        mov     eax, DWORD PTR [rbp-4]
        cdqe
        movzx   eax, BYTE PTR x[rax]
        movzx   eax, al
        cmp     edx, eax
        je      .L3
        mov     edi, OFFSET FLAT:.LC0
        call    puts
        mov     eax, 1
        jmp     .L4
.L3:
        add     DWORD PTR [rbp-4], 1
.L2:
        cmp     DWORD PTR [rbp-4], 32
        jle     .L5
        mov     edi, OFFSET FLAT:.LC1
        call    puts
        mov     eax, 1
.L4:
        leave
        ret
```

I assumed .L5 is the entrypoint and what this assembly snippet does is the following:
- read the input string
- XOR the i-th byte with 19
- increment 1
- compare the result with the i-th character of the hard coded string x
- if equal increment the counter and proceed otherwise break and print .LC0
- if all match then print .LC1


So basically I need to write a script to iterate over the x string decrement 1 and XOR with 19:
```python
x = "v\200suizgahMsMa{\177d\200wMl}bMq|s\200\200w~uwo"

flag = ''.join([chr((ord(i) - 1) ^ 19) for i in x])

print(flag)

```

Flag: `flag{just_a_simple_xor_challenge}`

<hr>

## Dumper

<img src="{{img_root}}/info/dumper.png" alt="Dumper">

By taking a look at the binary using PE-bear I found this in the section headers:

<img src="{{img_root}}/challenges/dumper/1.png" alt="PE-bear before">

Since it's dumped from memory then it will follow the section alignment so I changed each raw address to its corresponding virtual address, and also the raw size of the first section `.textbss` to the difference between the first two sections' addresses `11000 - 1000 = 10000`


<img src="{{img_root}}/challenges/dumper/2.png" alt="PE-bear after">

And by running the binary I got the flag

Flag: `flag{Successfully_Done_123456}`

<hr>

## ezez keygen2

<img src="{{img_root}}/info/ezez_keygen2.png" alt="ezez keygen2">

I already solved this challenge in [CyberTalents Cairo university CTF 2019](http://t1m3m.github.io/posts/cybertalents-cairo-university-2019-ctf/#ezez-keygen-2){:target="_blank"} and It was a nice coincidence because this was the first challenge I ever solved in the reverse engineering realm 😄

<hr>

## Kill Joy

<img src="{{img_root}}/info/kill_joy.png" alt="Kill Joy">

The binary is obfuscated and I didn't know where to start so i took a look at the strings on IDApro and I saw this interesting string:

<img src="{{img_root}}/challenges/kill_joy/1.png" alt="IDApro strings">

And by following its reference I got a function which I renamed to be `main`, It MOVes values to the memory at the start and terminates them with a zero so I copied these interesting variables:

<img src="{{img_root}}/challenges/kill_joy/2.png" alt="Values transferred to memory">

Then in the pseudocode an interesting functions for the first time:

<img src="{{img_root}}/challenges/kill_joy/3.png" alt="Main pseudocode">

The function [CreateToolhelp32Snapshot](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot){:target="_blank"} which basically with parameter 2 (TH32CS_SNAPPROCESS) returns a handle to all processes in the system

With [Process32FirstW](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32firstw){:target="_blank"} it gets the information of the first process in the snapshot then it iterates using [Process32NextW](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32nextw){:target="_blank"} through all the processes inside a while loop until it reaches the current process, both returns the entry to the process in the second parameter `pe`

Then it gets the executable name for the current process using the member [szExeFile](https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32w){:target="_blank"} in our case `Kill_Joy.exe`

The for loop shifts the letters to be:
```
lliK
yoJ_
exe.
```
And I knew from the initial and max value of j that it expects 32 characters as the filename of the binary!

The second for loop I guessed it's encrypting the filename after shifting as blocks of two, and the third for loop comparing the encrypted result to hard coded values which MUST be equal

So now the flag should be as the binary name + ".exe" and all should be 32 chars ex: `flag{AAAAAAAAAAAAAAAAAAAAAA}.exe`

Now I need to know:
- The key (if available)
- The hard coded encrypted data
- The encryption algorithm

By setting a breakpoint on the call to get the arguments value I saw an address `unk_14001D050` and the data to be encrypted `lliKyoJ_` and a constant number `32`:

<img src="{{img_root}}/challenges/kill_joy/4.png" alt="encryption call">

Following this address showed me interesting 16 bytes:
`34 12 56 34 23 34 1F 11 37 33 33 01 10 79 D5 34`

Then digging deeper to the call instruction I faced the encryption function:
<img src="{{img_root}}/challenges/kill_joy/4.png" alt="encryption function">

The value `0x9E3779B9` usually is the delta for the TEA cipher but the sum increment falls between 2 increments here so it's the updated version [XTEA](https://en.wikipedia.org/wiki/XTEA){target="_blank"}

I had the encrypted values (from the MOVes instructions above) and the key and the algorithm and the constant number `32` which is the number of rounds, the decryption C++ script is the next step but before that I rearranged the key to be of 4 blocks each of size 4 bytes in little-endian (that's how XTEA works)

```c++
#include <iostream>

using namespace std;

int main(){

    uint32_t ciphertext[4][2] = {
            {0xD6F74320, 0x636A7B0A},
            {0xEEC58E45, 0x5F1E3AF5},
            {0x14D72088, 0x819BF516},
            {0x10A4D83A, 0x2C1001E7}
    };

    uint32_t key[4] = {0x34561234, 0x111F3423, 0x01333337, 0x34D57910};

    int num_rounds = 32;

    for(int j=0; j < 4; j++){

        unsigned int i;
        uint32_t v0=ciphertext[j][0], v1=ciphertext[j][1],
            delta=0x9E3779B9, sum=delta*num_rounds;

        for (i=0; i < num_rounds; i++) {
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
            sum -= delta;
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        }

        ciphertext[j][0]=v0; ciphertext[j][1]=v1;
    }

    for (int i=0; i < 4; i++)
        printf("%x %x\n", ciphertext[i][0], ciphertext[i][1]);
https://t1m3m.github.io/posts/PEscope-tool/

    return 0;
}
```

output:
```
666c6167 7b746834
74735f68 30775f79
30755f73 75727631
76335f7d 2e657865
```

And then I decrypted the values using icyberchef `from hex` the result was the binary name "flag{th4ts_h0w_y0u_surv1v3_}.exe"

Flag: `flag{th4ts_h0w_y0u_surv1v3_}`

<hr>

## PE M0nSt3r

<img src="{{img_root}}/info/pe_monster.png" alt="PE M0nSt3r">

Firstly, I ran initial analysis on the binary using my tool [PEscope](https://t1m3m.github.io/posts/PEscope-tool/){:target="_blank"} to get some ***basic static analysis*** information:

<img src="{{img_root}}/challenges/pe_monster/1.png" alt="PEscope 1">
<img src="{{img_root}}/challenges/pe_monster/2.png" alt="PEscope 2">

I found some interesting APIs such as: `CreateProcessW`, `VirtualAlloc`, `VirtualAllocEx`, `VirtualProtect` from KERNEL32.dll and `NtResumeThread`, `NtUnmapViewOfSection`, `NtWriteVirtualMemory` from ntdll.dll. It seems like the binary is doing process hollowing!

I knew It's time for a ***basic dynamic analysis*** so running the binary gave me this output:

<img src="{{img_root}}/challenges/pe_monster/3.png" alt="basic dynamic analysis">

Remember that number `5344` because we will use it soon, on process hacker tool I saw the sub process created while waiting for input:

<img src="{{img_root}}/challenges/pe_monster/4.png" alt="process hacker">

I looked at IDApro for an ***advanced static analysis*** and there were only an obfuscated function wmain that's doing the unpacking logic so I jumped directly to x64dbg for ***advanced dynamic analysis*** to extract that packed file

In x64dbg after opening the binary first thing I set breakpoints at those interesting APIs I was more interested in `VirtualAlloc` and `NtResumeThread` because the first allocates a region in memory and returns the address to that region, and the latter moves the thread from suspended mode to running mode and this thread is basically the unpacked binary so I can dump its memory to a file!

This when it hit `VirtualAlloc`:

<img src="{{img_root}}/challenges/pe_monster/5.png" alt="x64dbg VirtualAlloc hit">

Then by `step into` > `step til return` I got the return value in **RAX** register:

<img src="{{img_root}}/challenges/pe_monster/6.png" alt="x64dbg VirtualAlloc return">

Now I got the allocated memory region that will be hollowed, resuming execution until I hit `NtResumeThread` gave me the nice unpacked binary:

<img src="{{img_root}}/challenges/pe_monster/7.png" alt="x64dbg unpacked dump">

Now to dump this memory to a file: `right-click` on dump below > `Follow in Memory Map` > `right-click` in the selected memory > `Dump Memory to File`

By saving this I got the raw unpacked file but there is a problem when running the binary it terminates immediately so maybe this is a problem that need to be fixed, something which is pretty common when dumping a binary from memory! So I checked it with PE-bear:

<img src="{{img_root}}/challenges/pe_monster/8.png" alt="PE-bear">

I noticed the `Entry Point` is zero which is unrealistic, but do you remember the number above? `5344`? I told you to remember it! Okay, no problem! converting that to hex `0x14e0` and changing the `Entry Point` to it and saving the changes should solve the issue!

Now the binary is up and running, The next step is to reverse it! I looked at the `main` function graph view to get a bird eye view of what's going on and I found the same obfuscation of the `wmain` in the previous packed file but more simple as it has few blocks below:

<img src="{{img_root}}/challenges/pe_monster/9.png" alt="IDApro overview">

<img src="{{img_root}}/memes/madness.gif" alt="This is madness!">

After the CTF I knew this obfuscation is called "OLLVM" and has a deobfuscator called [MODeflattener](https://github.com/mrT4ntr4/MODeflattener){:target="_blank"}, but I didn't know that so I worked with what I had!

I noticed the obfuscation pattern, the small blocks above with this storm-like shape acts as decision makers and there is a decision variable that has an arbitrary value that's calculated in the end of each below blocks and some of the small blocks are just moving the value to that decision variable nothing else, so to defeat that I needed to:
- notice the important blocks below depending on length of instruction and operations
- set breakpoints at the start of that block and debugging to understand the logic

<img src="{{img_root}}/challenges/pe_monster/10.png" alt="IDApro breakpoints">

The small blocks included here do an increment so I set a breakpoint to know which iteration I am in, but I found this pseudocode snippet is interesting:

<img src="{{img_root}}/challenges/pe_monster/11.png" alt="IDApro snippet pseudocode">

The code basically:
- Stores the input bytes as little-endian (the below snipped which is executed first)
- Repeats that 8 times each with 4 bytes storing so the flag length should be 32 characters
- Encrypting the input with a hard coded key
- Comparing the result with previously encrypted hard coded values

So the steps to the solution are:
- Get the key
- Get the encrypted values
- Decryption (if possible)

I got the key first by stepping over `lea rdx, hardcoded` instruction and following the address at `rdx` register in memory:

<img src="{{img_root}}/challenges/pe_monster/12.png" alt="Key in memory">

Then the encrypted values by hitting the breakpoint at the comparing block and stepping over few instructions until hitting the `cmp` instruction:

<img src="{{img_root}}/challenges/pe_monster/13.png" alt="Key in memory">

And by following `var_70` in the memory dump I got the encrypted values:

<img src="{{img_root}}/challenges/pe_monster/14.png" alt="encrypted values in memory">

What's left now is to know the encryption algorithm and this pseudocode of the encryption function made it easier:

<img src="{{img_root}}/challenges/pe_monster/15.png" alt="Encryption algorithm">

This looks like the algorithm in the previous challenge but notice the sum decrement is at first which makes it the original [TEA cipher](https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm){:target="_blank"}

But one problem remains the delta is decremented here not incremented! I considered it to be equal to: `delta += -0x61C88647` and after searching it turns out it can be the original delta `0x9E3779B9` because `0x9E3779B9 - 0x100000000 = -0x61C88647` and therefore the sum can be the original value `0xC6EF3720`

I arranged the endianness for the key and the encrypted values then I wrote a C++ script for TEA decryption:
```c++
#include <iostream>

using namespace std;

int main() {

    uint32_t ciphertext[4][2] = {
      {0x21C2FB7C, 0xC553E97B},
      {0x9E893411, 0xFF5A7E60},
      {0xB12CA755, 0xA5D55898},
      {0x8A08537A, 0x663511D1}
    };

    uint32_t key[4] = {0x34561234, 0x111F3423, 0x34D57910, 0x00989034};

    for (int j = 0; j < 4; j++) {

        unsigned int i;
        uint32_t v0 = ciphertext[j][0], v1 = ciphertext[j][1], delta = 0x9E3779B9, sum = 0xC6EF3720;
        uint32_t k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3];

        for (i = 0; i < 32; i++) {
            v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
            v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
            sum -= delta;
        }

        ciphertext[j][0] = v0; ciphertext[j][1] = v1;
    }

    for (int i = 0; i < 4; i++)
        printf("%x %x\n", ciphertext[i][0], ciphertext[i][1]);


    return 0;
}
```

I ran the script and decrypted the hex values using icyberchef using `from hex` recipe and I got the flag!

Flag: `flag{W3Lc0m3_t0_r3v3rs3_L4nd-_-}`

Now it's time for a cuppa TEA

<img src="{{img_root}}/memes/TEA.gif" alt="TEA!">
