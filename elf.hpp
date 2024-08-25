#define SHT_PROGBITS 0x01
#define SHT_STRTAB 0x03
#define SHT_RELA 0x04
#define SHT_HASH 0x05
#define SHT_DYNAMIC 0x06
#define SHT_REL 0x09
#define SHT_NOBITS 0x08
#define SHT_DYNSYM 0x0B
#define SHT_INIT_ARRAY 0x0E
#define SHT_FINI_ARRAY 0x0F
#define SHT_GNU_HASH 0x6ffffff6

#define SHF_WRITE 0x01
#define SHF_ALLOC 0x02
#define SHF_EXECINSTR 0x04
#define SHF_INFO_LINK 0x40

// .rela.dyn
#define DT_RELA 0x07
#define DT_RELASZ 0x08
#define DT_RELAENT 0x09
#define DT_RELACOUNT 0x6ffffff9

// .rel.dyn
#define DT_REL 0x11
#define DT_RELSZ 0x12
#define DT_RELENT 0x13
#define DT_RELCOUNT 0x6ffffffa

// .rela.plt / .rel.plt
#define DT_JMPREL 0x17
#define DT_PLTRELSZ 0x02
#define DT_PLTREL 0x14

// .dynsym (already covered by MOD0 header)
#define DT_SYMTAB 0x06
#define DT_SYMENT 0x0B

// .dynstr (already covered by MOD0 header)
#define DT_STRTAB 0x05
#define DT_STRSZ 0x0A

// .init_array
#define DT_INIT_ARRAY 0x19
#define DT_INIT_ARRAYSZ 0x1B

// .fini_array
#define DT_FINI_ARRAY 0x1A
#define DT_FINI_ARRAYSZ 0x1C

#define DT_INIT 0x0C
#define DT_FINI 0x0D

// .gnu.hash
#define DT_GNU_HASH 0x6ffffef5

// .hash
#define DT_HASH 0x04

// .got
#define DT_PLTGOT 0x03

#define ET_DYN 0x03

#define PF_X 0x01
#define PF_W 0x02
#define PF_R 0x04

struct Elf64Segment {
    uint32_t p_type = 0;
    uint32_t p_flags = 0;
    uint64_t p_offset = 0;
    uint64_t p_vaddr = 0;
    uint64_t p_paddr = 0;
    uint64_t p_filesz = 0;
    uint64_t p_memsz = 0;
    uint64_t p_align = 0;
};

struct Elf64Section {
    uint32_t sh_name = 0;
    uint32_t sh_type = 0;
    uint64_t sh_flags = 0;
    uint64_t sh_addr = 0;
    uint64_t sh_offset = 0;
    uint64_t sh_size = 0;
    uint32_t sh_link = 0;
    uint32_t sh_info = 0;
    uint64_t sh_addralign = 1;
    uint64_t sh_entsize = 0;
};

struct ElfArm64Header {
    char e_ident[16] = { '\x7F', 'E', 'L', 'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint16_t e_type = ET_DYN;
    uint16_t e_machine = 0xB7; // aarch64
    uint32_t e_version = 1;
    uint64_t e_entry = 0;
    uint64_t e_phoff = sizeof(ElfArm64Header);
    uint64_t e_shoff = 0; // fill me
    uint32_t e_flags = 0;
    uint16_t e_ehsize = sizeof(ElfArm64Header);
    uint16_t e_phentsize = sizeof(Elf64Segment);
    uint16_t e_phnum = 0; // fill me
    uint16_t e_shentsize = sizeof(Elf64Section);
    uint16_t e_shnum = 0; // fill me
    uint16_t e_shstridx = 0; // fill me
};

struct NXElfHeader: public ElfArm64Header {
    Elf64Segment p_text, p_ro, p_data, p_bss, p_dyn;
    NXElfHeader() {
        e_phnum = 5;
    }
};

static_assert(sizeof(ElfArm64Header) == 0x40);
static_assert(sizeof(Elf64Segment) == 0x38);
static_assert(sizeof(Elf64Section) == 0x40);

#define PT_LOAD 1
#define PT_DYNAMIC 2