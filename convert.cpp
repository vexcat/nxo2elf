#include "program.hpp"

void pad_output(FILE *fout, uint32_t padding) {
    std::vector<uint8_t> zeroes;
    zeroes.resize(0x1000);
    while (padding) {
        auto step = padding < zeroes.size() ? padding : zeroes.size();
        fwrite(zeroes.data(), step, 1, fout);
        padding -= step;
    }
}

void align_output(FILE *fout, uint32_t align) {
    pad_output(fout, (uint32_t)(-ftell(fout)) & (align - 1));
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("usage: %s in.nro out.nrs\n", argv[0]);
        printf("or     %s in.nso out.nss\n", argv[0]);
        return 0;
    }
    auto fout = fopen(argv[2], "wb");
    if (!fout) {
        perror("fopen output");
        return 1;
    }
    auto program = NXOProgram::load_file(argv[1]);
    printf("0x%08X program bytes (%08X + %08X + %08X)\n", program.text_seg.size + program.ro_seg.size + program.data_seg.size, program.text_seg.size, program.ro_seg.size, program.data_seg.size);
    auto dyn = program.dynamic();
    // printf(".dynamic %08X-%08X\n", dyn.addr, dyn.addr + dyn.size);
    auto sections = program.sections();
    for(const auto &section: sections) {
        printf("%s %08llX-%08llX\n", section.name.c_str(), section.addr, section.addr + section.size);
    }
    const auto data_offset = 0x10000;
    std::vector<Elf64Section> elf_sections;
    std::vector<char> shstrtab;
    for(auto &section: sections) {
        uint32_t stridx = shstrtab.size();
        shstrtab.insert(shstrtab.end(), section.name.data(), section.name.data() + section.name.size() + 1);
        uint64_t entsize = 0;
        if (section.type == SHT_RELA || section.type == SHT_DYNSYM) entsize = 0x18;
        if (section.type == SHT_REL || section.type == SHT_DYNAMIC) entsize = 0x10;
        if (section.type == SHT_HASH) entsize = 0x04;
        elf_sections.push_back({
            stridx,
            section.type, section.flags,
            section.addr, data_offset + program.offset(section.addr), section.size,
            section.link, section.info,
            1,
            entsize
        });
    }
    uint32_t shstrtab_stridx = shstrtab.size();
    const char* shstrtab_name = ".shstrtab";
    shstrtab.insert(shstrtab.end(), shstrtab_name, shstrtab_name + 10);
    elf_sections.push_back({
        shstrtab_stridx,
        SHT_STRTAB, 0x00,
        0,
        data_offset + align_size(program.text_seg.size) + align_size(program.ro_seg.size) + align_size(program.data_seg.size),
        shstrtab.size(),
        0,
        0,
        1,
        0
    });
    NXElfHeader elf_header;
    elf_header.e_shnum = sections.size() + 1;
    elf_header.e_shstridx = sections.size();
    elf_header.e_shoff = data_offset + align_size(program.text_seg.size) + align_size(program.ro_seg.size) + align_size(program.data_seg.size) + align_size(shstrtab.size());
    elf_header.p_text = {
        PT_LOAD, PF_X | PF_R,
        data_offset + program.offset(program.text_seg.addr),
        program.text_seg.addr, program.text_seg.addr,
        program.text_seg.size, program.text_seg.size,
        0x1000
    };
    elf_header.p_ro = {
        PT_LOAD, PF_R,
        data_offset + program.offset(program.ro_seg.addr),
        program.ro_seg.addr, program.ro_seg.addr,
        program.ro_seg.size, program.ro_seg.size,
        0x1000
    };
    elf_header.p_data = {
        PT_LOAD, PF_R | PF_W,
        data_offset + program.offset(program.data_seg.addr),
        program.data_seg.addr, program.data_seg.addr,
        program.data_seg.size, program.data_seg.size,
        0x1000
    };
    auto bss_addr = program.data_seg.addr + program.data_seg.size;
    elf_header.p_bss = {
        PT_LOAD, PF_R | PF_W,
        data_offset + program.offset(program.data_seg.addr) + program.data_seg.size,
        bss_addr, bss_addr,
        0, program.bss_size,
        0x1000
    };
    auto dynsect = program.dynamic_seg();
    elf_header.p_dyn = {
        PT_DYNAMIC, PF_R | PF_W,
        data_offset + program.offset(dynsect.addr),
        dynsect.addr, dynsect.addr,
        dynsect.size, dynsect.size,
        0x08
    };
    fwrite(&elf_header, sizeof(elf_header), 1, fout);
    pad_output(fout, data_offset - ftell(fout));
    fwrite(program.text.data(), program.text.size(), 1, fout);
    align_output(fout, 0x1000);
    fwrite(program.ro.data(), program.ro.size(), 1, fout);
    align_output(fout, 0x1000);
    fwrite(program.data.data(), program.data.size(), 1, fout);
    align_output(fout, 0x1000);
    fwrite(shstrtab.data(), shstrtab.size(), 1, fout);
    align_output(fout, 0x1000);
    fwrite(elf_sections.data(), sizeof(Elf64Section), elf_sections.size(), fout);
    align_output(fout, 0x1000);
    fclose(fout);
    return 0;
}