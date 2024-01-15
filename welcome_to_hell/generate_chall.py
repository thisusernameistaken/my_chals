from binaryninja import (
    open_view,
    BinaryView,
    Architecture,
    Platform,
    Type
)
from pwn import *
import os

flag  = b"UMASS{sr0p_n_r3v_is_h3ll}"

context.arch="amd64"
elf = ELF.from_assembly("ret")

elf64_type = """
typedef uint64_t	Elf64_Addr;
typedef uint16_t	Elf64_Half;
typedef uint64_t	Elf64_Off;
typedef int32_t		Elf64_Sword;
typedef int64_t		Elf64_Sxword;
typedef uint32_t	Elf64_Word;
typedef uint64_t	Elf64_Lword;
typedef uint64_t	Elf64_Xword;
typedef struct {
        Elf64_Word      st_name;
        unsigned char   st_info;
        unsigned char   st_other;
        Elf64_Half      st_shndx;
        Elf64_Addr      st_value;
        Elf64_Xword     st_size;
} Elf64_Sym;
"""
address_start = 0x6c6c65480000

elf_bv = open_view(elf.path)
elf_types = [(x,elf_bv.types[x]) for x in elf_bv.type_names]
bv = BinaryView.new()
bv.arch = Architecture['x86_64']
bv.platform = Platform['linux-x86_64']

for t in elf_types:
    bv.define_user_type(t[0],t[1])
more_types = bv.parse_types_from_string(elf64_type)
for name, t in more_types.types.items():
    bv.define_user_type(name,t)

symbols = [{"name":b"Let's Go!!1!1!!!!","addr":0,"type":"function"}]

sc = asm("mov r15, [rsp+0x10]")
sc += asm("mov r10, 0")
sc += b"\xeb\x10"
sc += b"\x00small_function\x00"
sc += asm(shellcraft.amd64.linux.mmap_rwx(address=0x41414141000,size=8192*2))
sc += asm("mov r11, 0")
sc += b"\xeb\x0f"
sc += b"\x00useful_gadget\x00"
sc += asm(shellcraft.amd64.linux.open("r15"))
sc += asm("mov r11, 0")
sc += b"\xeb\x10"
sc += b"\x00exiting_please\x00"
sc += asm(shellcraft.amd64.linux.syscall(8,"rax",0xb0,0))
sc += asm("mov r13, 0")
sc += b"\xeb\x30"
sc += b"\x00long_function_name_but_actually_short_function\x00"
sc += asm(shellcraft.amd64.linux.read(3,0x41414141000,0x2f50))
sc += asm("mov r14, 0")
sc += b"\xeb\x12"
sc += b"\x00shrt_fnc_shrt_nm\x00"
sc += asm("""
    xor rcx, rcx
    mov rax, rsi
    sub rsi, 1
    mov rbx, 0x69
    loop:
        xor byte [rsi], rbx
        inc rsi
        inc rcx
        cmp rcx, 0x2f50
        jne loop
        jmp rax
""")
sc += b"\x00exit_call\x00"
sc += b"syscall_return\x00"

sc += b"A"*5


sym_names = sc.split(b"\x00")
i = 0
for s in sym_names:
    symbols.append({"name":s, "addr":i*0x11,"type":"function"})
    print(s)
    i+=1

SHSTRTAB_OFF = 0x3000+(0x40*5)
shstrtab_data = b"\x00.text\x00.strtab\x00.shstrtab\x00.symtab\x00"
SYMTAB_OFF = SHSTRTAB_OFF+len(shstrtab_data)
SYMTAB_SIZE = 0x18
symtab_data = b"\x00"*0x18
strtab_data = b"\x00"
STRTAB_SIZE = 1
for sym_dict in symbols:
    SYMTAB_SIZE += 0x18 #size of one symbol
    symtab_data += p32(STRTAB_SIZE)#name
    if sym_dict['type'] == "function": #info
        symtab_data += p8(0x12)
    else:
        symtab_data += p8(0x10)
    symtab_data += p8(0) #other
    symtab_data += p16(4) #shndx
    symtab_data += p64(sym_dict['addr']) #value
    symtab_data += p64(0) #size
    #add to strtab
    strtab_data += sym_dict['name']+b"\x00"

    STRTAB_SIZE = len(strtab_data)
STRTAB_OFF = SYMTAB_OFF + len(strtab_data)
# elf header
bv.write(0,b"\x00"*0x40)
bv.define_data_var(0,bv.types['Elf64_Header'])
elf_header = bv.get_data_var_at(0)
# copy over existing ident
elf_header['ident'].value = elf_bv.parent_view.read(0,0x40)
elf_header['type'].value = p16(2)
elf_header['machine'].value = p16(0x3e)
elf_header['version'].value = p32(elf_bv.parent_view.get_data_var_at(0)['version'].value)
elf_header['program_header_offset'].value = p32(0x40) #after the Elf64_Header
elf_header['section_header_offset'].value = p64(0x3000) #after program header (0x38*2)+0x40
elf_header['flags'].value = p32(elf_bv.parent_view.get_data_var_at(0)['flags'].value)
elf_header['header_size'].value = p16(0x40) # size of this struct
elf_header['program_header_size'].value = p16(0x38) # size of program header
elf_header['program_header_count'].value = p16(0x2) 
elf_header['section_header_size'].value = p16(0x40)
elf_header['section_header_count'].value = p16(0x5) # maybe only need 5
elf_header['string_table'].value = p16(0x2) 
# program header (0x38*2) # header and code
bv.write(0x40,elf_bv.parent_view.read(0x40,0x70))
bv.define_data_var(0x40,Type.array(bv.types["Elf64_ProgramHeader"],2))
header_segment = bv.get_data_var_at(0x40)[0]
header_segment['file_size'].value = p64(0xb0)
header_segment['memory_size'].value = p64(0xb0)

code_segment = bv.get_data_var_at(0x40)[1]
code_segment['virtual_address'].value = p64(address_start)
code_segment['physical_address'].value = p64(address_start)
code_segment['align'].value = p64(0x3000)
code_segment['flags'].value = p32(5)
# padding
input_addr = 0x41414142fd0

binary = asm("mov rbp, rsp")
binary += asm("sub rsp, 0x500")
binary += asm(shellcraft.amd64.linux.write(1,"Welcome to the challenge!\n",len("Welcome to the challenge!\n")))
binary += asm(shellcraft.amd64.linux.write(1,"Enter the flag: ",len("Enter the flag: ")))
binary += asm(shellcraft.amd64.linux.read(0,input_addr,48))
binary += asm("mov rdx, rax")
binary += asm("""
mov rdi, 0x19
cmp rdx, rdi
je good
mov rax, 0x3c
syscall
good:
nop
""")
call_sigreturn = asm("""
lea rsp, [rip+0x9]
mov rax, 0xf
syscall""")

lose_addr = 0x414141410a0
a = 0x414141410b8
binary += call_sigreturn
for i, flag_char in enumerate(flag):
    a+=0xfa
    frame = SigreturnFrame(kernel='amd64')
    frame.rax = (0xc01db3af^((flag[i]<<i+11)|random.randrange(0xfff)))
    frame.rsi = 0xffffffffffffffff
    frame.rcx = i
    frame.r8 = 0xc01db3af
    frame.r9 = input_addr-1
    frame.rdx = lose_addr
    frame.rip = a
    binary += bytes(frame)
    binary += asm("""
    add r9, rcx
    mov r10, byte [r9]
    xor rax, r8
    add cl, 11
    shr rax, cl
    cmp al, r10b
    je good
    jmp rdx
    good:
    nop
    """)
    binary += call_sigreturn
    a+=0x26

frame = SigreturnFrame(kernel='amd64')
frame.rax = 1
frame.rdi = 1
frame.rsi = 0x41414142fd0
frame.rdx = 0x19
frame.rip = 0x6c6c65480769 #syscall
binary += bytes(frame)
enc_binary = b""
for x in range(len(binary)):
    enc_binary += bytes([binary[x] ^ (0x69)])

enc_binary = enc_binary.ljust(0x2f50,b"Z")
bv.write(0xb0, enc_binary) # this is where flag checker part goes

#section header
bv.write(0x3000, b"\x00"*(0x40*5))
bv.define_data_var(0x3000,Type.array(bv.types['Elf64_SectionHeader'],5))
section_headers = bv.get_data_var_at(0x3000)
#progbits
prog_bits = section_headers[1]
prog_bits['name'].value = p32(1) # .text first on string table
prog_bits['type'].value = p32(1) # SHT_PROGBITS
prog_bits['flags'].value = p64(7) # write|alloc|execinstr
#shstrtab
shstrtab = section_headers[2]
shstrtab['name'].value = p32(0xf)
shstrtab['type'].value = p32(3)
shstrtab['offset'].value = p64(SHSTRTAB_OFF)
shstrtab['address'].value = p64(address_start+SHSTRTAB_OFF-0x3000)
shstrtab['size'].value = p64(len(shstrtab_data))
shstrtab['flags'].value = p64(3) # write|alloc|execinstr
#symtab
sym_table = section_headers[3]
sym_table['name'].value = p32(0x19)
sym_table['type'].value = p32(2) #.symtab
sym_table['offset'].value = p64(SYMTAB_OFF) # (0x40*5) + 0xb0
sym_table['size'].value = p64(SYMTAB_SIZE) # SYMTAB size
sym_table['link'].value = p32(4) #link to strtab
sym_table['entry_size'].value = p64(0x18) # symbol size
sym_table['address'].value = p64(address_start+SYMTAB_OFF-0x3000)
sym_table['info'].value = p32(1) # start of first global
sym_table['flags'].value = p64(3) # write|alloc|execinstr
# strtab
strtab = section_headers[4]
strtab['name'].value = p32(7)#.strtab
strtab['type'].value = p32(3) #strtab
strtab['offset'].value = p64(SYMTAB_OFF+len(symtab_data))
strtab['address'].value = p64(address_start+SYMTAB_OFF+len(symtab_data)-0x3000)
strtab['size'].value = p64(STRTAB_SIZE)
strtab['flags'].value = p64(3) # write|alloc|execinstr

bv.write(SHSTRTAB_OFF,shstrtab_data)
bv.write(SYMTAB_OFF,symtab_data)
bv.write(SYMTAB_OFF+len(symtab_data),strtab_data)
# code
CODE_OFF = SYMTAB_OFF+len(symtab_data)+len(strtab_data)
code_segment['offset'].value = p64(CODE_OFF)

src_code = """
void main()
{{
    void* dest = (void*) {};
    char buf[3];
    int val;
    __syscall(0,0,buf,3);
    val = atoi(buf);
    dest += (val*0x11);
    goto *dest;
}}
""".format(address_start+0x74a)

with open("main_code","w") as f:
    f.write(src_code)

scc_bin = "/home/chris/Tools/binaryninja/plugins/scc"
cmd = f"{scc_bin} main_code --arch amd64 --concat -o main_bin"
print("running scc",cmd)
os.system(cmd)
with open("main_bin","rb") as f:
    code_bytes = f.read()

code_bytes = code_bytes.replace(b"\x8b\xc3",b"\x48\x89\xd8\x90\x90\x90") #fix first problem
code_bytes = code_bytes.replace(b"\x44\x8b\xcb",b"\x49\x89\xd9") #fix second
code_bytes = code_bytes.replace(b"\x44\x8b\xd3",b"\x49\x89\xda") #fix third

code_str = ""
for x in range(0xfff):
    code_str+="""
    mov rdi, {}
    mov rax, 0x3c
    syscall
    ret
    """.format(x)

ret_code = Architecture['x86_64'].assemble(code_str)
code_bytes += ret_code

bv.write(CODE_OFF,code_bytes)

code_segment_size = CODE_OFF+len(code_bytes)-0x3000
code_segment['offset'].value = p64(0x3000)
code_segment['file_size'].value = p64(code_segment_size)
code_segment['memory_size'].value = p64(code_segment_size)
prog_bits['offset'].value = p64(CODE_OFF)
prog_bits['size'].value = p64(len(code_bytes))
prog_bits['address'].value = p64(address_start+CODE_OFF-0x3000)
elf_header['entry'].value = p64(address_start+CODE_OFF-0x3000)
entry = address_start+CODE_OFF-0x3000
# update symbols
bv.define_data_var(SYMTAB_OFF, Type.array(bv.types['Elf64_Sym'],len(symbols)+1))
all_symbols = bv.get_data_var_at(SYMTAB_OFF)
all_symbols[1]['st_value'].value = p64(entry)
i = 2
addr = entry+0x97
while i < len(symbols)+1:
    sym = all_symbols[i]
    sym['st_value'].value = p64(addr+sym['st_value'].value)
    i+=1


bv.save("welcome_to_hell")