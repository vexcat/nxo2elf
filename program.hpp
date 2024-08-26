#include <cstdint>
#include <vector>
#include <string>
#include <stdexcept>
#include <cstdio>
#include <unordered_map>
#include <unordered_set>
#include <lz4.h>
#include "elf.hpp"

static uint32_t align_size(uint32_t size) {
    return (size + 0xFFF) & ~0xFFF;
}

const std::unordered_set<uint64_t> known_dynamic = {
    DT_RELA,
    DT_RELASZ,
    DT_RELAENT,
    DT_RELACOUNT,
    DT_REL,
    DT_RELSZ,
    DT_RELENT,
    DT_RELCOUNT,
    DT_JMPREL,
    DT_PLTRELSZ,
    DT_PLTREL,
    DT_SYMTAB,
    DT_SYMENT,
    DT_STRTAB,
    DT_STRSZ,
    DT_INIT_ARRAY,
    DT_INIT_ARRAYSZ,
    DT_FINI_ARRAY,
    DT_FINI_ARRAYSZ,
    DT_INIT,
    DT_FINI,
    DT_GNU_HASH,
    DT_HASH,
    DT_PLTGOT
};

struct GNUHashHeader {
    uint32_t nbuckets;
    uint32_t symoffset;
    uint32_t bloom_size;
    uint32_t bloom_shift;
};

struct ELFSection {
    std::string name;
    uint32_t type;
    uint64_t flags;
    uint64_t addr, size;
    uint32_t link, info;
};

struct ELFRela {
    uint64_t offset;
    uint64_t info;
    uint64_t addend;
};

struct ELFRel {
    uint64_t offset;
    uint64_t info;
};

struct NXOSegment {
    uint32_t addr;
    uint32_t size;
    bool contains(uint32_t taddr, uint32_t tsize) {
        return taddr >= addr && taddr + tsize <= addr + size;
    }
};

struct ModuleHeader {
    uint32_t reserved1;
    uint32_t mod0offset;
    uint32_t nnsdkvers;
    uint32_t reserved2;
};

struct NROHeader {
    ModuleHeader mod;
    char magic[4];
    uint32_t version, size, flags;
    NXOSegment text, ro, data;
    uint32_t bss_size, reserved3;
    char modid[0x20];
    uint32_t dso_offset;
    uint32_t reserved4;
    NXOSegment api_info, dynstr, dynsym;
};

struct NSOSegment {
    uint32_t offset;
    uint32_t addr;
    uint32_t size; // decompressed size
};

struct NSOHeader {
    char magic[4];
    uint32_t version;
    uint32_t reserved1;
    uint32_t flags;
    NSOSegment text;
    uint32_t modname_offset;
    NSOSegment ro;
    uint32_t modname_size;
    NSOSegment data;
    uint32_t bss_size;
    uint8_t modid[0x20];
    uint32_t text_file_size;
    uint32_t ro_file_size;
    uint32_t data_file_size;
    uint8_t reserved2[0x1C];
    NXOSegment api_info, dynstr, dynsym;
    uint8_t text_hash[0x20];
    uint8_t ro_hash[0x20];
    uint8_t data_hash[0x20];
};

static_assert(sizeof(NSOHeader) == 0x100);

struct MODHeader {
    char magic[4];
    uint32_t dyn;
    uint32_t bss_start;
    uint32_t bss_end;
    uint32_t eh_frame_hdr_start;
    uint32_t eh_frame_hdr_end;
    uint32_t runtime_mod;
};

static_assert(sizeof(NROHeader) == 0x80);

struct DynEntry {
    uint64_t tag;
    uint64_t value;
};

struct NXOProgram {
    NXOSegment text_seg, ro_seg, data_seg;
    uint32_t bss_size;
    NXOSegment api_info, dynstr, dynsym;
    std::vector<uint8_t> text, ro, data;
    bool is_nro = true;
    uint8_t *resolve(uint32_t addr, uint32_t size = 0) {
        if (text_seg.contains(addr, size)) return text.data() + addr - text_seg.addr;
        if (ro_seg  .contains(addr, size)) return ro  .data() + addr - ro_seg  .addr;
        if (data_seg.contains(addr, size)) return data.data() + addr - data_seg.addr;
        return nullptr;
    }
    uint32_t offset(uint32_t addr) {
        if (text_seg.contains(addr, 0)) return addr - text_seg.addr;
        if (ro_seg  .contains(addr, 0)) return align_size(text.size()) + addr - ro_seg.addr;
        return align_size(text.size()) + align_size(ro.size()) + addr - data_seg.addr;
    }
    std::vector<uint8_t> read_bytes(uint32_t addr, uint32_t size) {
        auto ptr = resolve(addr, size);
        if (!ptr) throw std::runtime_error {"Address not found in NRO"};
        return {ptr, ptr + size};
    }
    template <typename T>
    T read_data(uint32_t addr) {
        T ret;
        auto ptr = resolve(addr, sizeof(T));
        if (!ptr) throw std::runtime_error {"Address not found in NRO"};
        memcpy(&ret, ptr, sizeof(T));
        return ret;
    }
    template <typename T>
    std::vector<T> read_arr(uint32_t addr, uint32_t count) {
        std::vector<T> ret;
        while(count--) {
            ret.push_back(read_data<T>(addr));
            addr += sizeof(T);
        }
        return ret;
    }

    static NXOProgram load_file(const char *filename) {
        FILE *fin = fopen(filename, "rb");
        if (!fin) throw std::runtime_error {"Failed to open file"};
        char ident[0x14];
        if (!fread(ident, sizeof(ident), 1, fin)) {
            fclose(fin);
            throw std::runtime_error {"Failed to read NRO/NSO magic"};
        }
        fseek(fin, 0, SEEK_SET);
        if (memcmp(ident + 0x10, "NRO0", 4) == 0) {
            return load_nro_file(fin);
        }
        if (memcmp(ident, "NSO0", 4) == 0) {
            return load_nso_file(fin);
        }
        fclose(fin);
        throw std::runtime_error {"Not an NRO or NSO file"};
    }

    static NXOProgram load_nso_file(FILE *fin) {
        NXOProgram prg;
        NSOHeader header;
        prg.is_nro = false;
        if(!fread(&header, sizeof(header), 1, fin)) {
            fclose(fin);
            throw std::runtime_error {"Failed to read NSO header"};
        }
        prg.text_seg = {header.text.addr, header.text.size};
        prg.ro_seg   = {header.ro  .addr, header.ro  .size};
        prg.data_seg = {header.data.addr, header.data.size};
        prg.bss_size = header.bss_size;
        prg.api_info = header.api_info;
        prg.dynstr = header.dynstr;
        prg.dynsym = header.dynsym;

        prg.text.resize(header.text.size);
        prg.ro.resize(header.ro.size);
        prg.data.resize(header.data.size);

        std::vector<uint8_t> filedata;

        filedata.resize(header.text_file_size);
        fseek(fin, header.text.offset, SEEK_SET);
        if(!fread(filedata.data(), filedata.size(), 1, fin)) {
            fclose(fin);
            throw std::runtime_error {"Failed to read NSO text segment"};
        }
        if (header.flags & 1) {
            LZ4_decompress_safe((const char*) filedata.data(), (char*) prg.text.data(), filedata.size(), prg.text.size());
        } else {
            prg.text = filedata;
        }

        filedata.resize(header.ro_file_size);
        fseek(fin, header.ro.offset, SEEK_SET);
        if(!fread(filedata.data(), filedata.size(), 1, fin)) {
            fclose(fin);
            throw std::runtime_error {"Failed to read NSO ro segment"};
        }
        if (header.flags & 2) {
            LZ4_decompress_safe((const char*) filedata.data(), (char*) prg.ro.data(), filedata.size(), prg.ro.size());
        } else {
            prg.ro = filedata;
        }

        filedata.resize(header.data_file_size);
        fseek(fin, header.data.offset, SEEK_SET);
        if(!fread(filedata.data(), filedata.size(), 1, fin)) {
            fclose(fin);
            throw std::runtime_error {"Failed to read NSO data segment"};
        }
        if (header.flags & 4) {
            LZ4_decompress_safe((const char*) filedata.data(), (char*) prg.data.data(), filedata.size(), prg.data.size());
        } else {
            prg.data = filedata;
        }


        fclose(fin);

        return prg;
    }

    static NXOProgram load_nro_file(FILE *fin) {
        NXOProgram prg;
        NROHeader header;
        prg.is_nro = true;
        if(!fread(&header, sizeof(header), 1, fin)) {
            fclose(fin);
            throw std::runtime_error {"Failed to read NRO header"};
        }
        prg.text_seg = header.text;
        prg.ro_seg = header.ro;
        prg.data_seg = header.data;
        prg.bss_size = header.bss_size;
        prg.api_info = header.api_info;
        prg.dynstr = header.dynstr;
        prg.dynsym = header.dynsym;

        prg.text.resize(header.text.size);
        prg.ro.resize(header.ro.size);
        prg.data.resize(header.data.size);
        fseek(fin, 0, SEEK_SET);
        if (
            !fread(prg.text.data(), prg.text.size(), 1, fin) ||
            !fread(prg.ro.data(), prg.ro.size(), 1, fin) ||
            !fread(prg.data.data(), prg.data.size(), 1, fin)
        ) {
            fclose(fin);
            throw std::runtime_error {"Failed to read NRO contents"};
        }
        fclose(fin);
        return prg;
    }
    MODHeader mod_info() {
        auto modheader = read_data<ModuleHeader>(0);
        auto off = modheader.mod0offset;
        auto ret = read_data<MODHeader>(off);
        if (memcmp(ret.magic, "MOD0", 4) != 0) {
            throw std::runtime_error {"Invalid MOD0"};
        }
        ret.dyn += off;
        ret.bss_start += off;
        ret.bss_end += off;
        ret.eh_frame_hdr_start += off;
        ret.eh_frame_hdr_end += off;
        ret.runtime_mod += off;
        return ret;
    }
    NXOSegment dynamic_seg() {
        // Start is stored in MOD0 header, but not end
        auto dyn = mod_info().dyn;
        if (!dyn) throw std::runtime_error {"No .dynamic section"};
        auto dyn_end = dyn;
        // Find DT_NULL (0)
        while (read_data<uint64_t>(dyn_end) != 0) {
            dyn_end += 16;
        }
        // End is just past DT_NULL entry
        dyn_end += 16;
        return {dyn, dyn_end - dyn};
    }
    std::unordered_map<uint64_t, uint64_t> dynamic() {
        std::unordered_map<uint64_t, uint64_t> ret;
        auto bounds = dynamic_seg();
        for(int i = 0; i < bounds.size - 16; i += 16) {
            auto entry = read_data<DynEntry>(bounds.addr + i);
            ret[entry.tag] = entry.value;
        }
        return ret;
    }
    
    std::vector<ELFSection> sections() {
        std::vector<ELFSection> ret;
        uint32_t dynstr_idx = 0;
        uint32_t dynsym_idx = 0;
        uint32_t got_idx = 0;
        uint32_t bss_end = data_seg.addr + data_seg.size + bss_size;
        ret.push_back({
            "",0,0,0,0,0,0
        });
        ret.push_back({
            is_nro ? ".rocrt_nro.init" : ".rocrt.init",
            SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
            text_seg.addr, 0x08,
            0, 0
        });
        if (is_nro) {
            ret.push_back({
                ".nro_header",
                SHT_PROGBITS, SHF_ALLOC | SHF_EXECINSTR,
                text_seg.addr + 0x08, 0x78,
                0, 0
            });
        }
        auto modheader = read_data<ModuleHeader>(0);
        if (modheader.mod0offset) {
            ret.push_back({
                is_nro ? ".rocrt_nro.info" : ".rocrt.info",
                SHT_PROGBITS, SHF_ALLOC,
                modheader.mod0offset, sizeof(MODHeader),
                0, 0
            });
        }
        if (api_info.size) {
            ret.push_back({
                ".api_info",
                SHT_PROGBITS, SHF_ALLOC,
                api_info.addr + ro_seg.addr, api_info.size,
                0, 0
            });
        }
        if (dynstr.size) {
            dynstr_idx = ret.size();
            ret.push_back({
                ".dynstr",
                SHT_STRTAB, SHF_ALLOC,
                dynstr.addr + ro_seg.addr, dynstr.size,
                0, 0
            });
        }
        if (dynsym.size) {
            dynsym_idx = ret.size();
            ret.push_back({
                ".dynsym",
                SHT_DYNSYM, SHF_ALLOC,
                dynsym.addr + ro_seg.addr, dynsym.size,
                dynstr_idx, 0x01
            });
        }
        if (modheader.mod0offset) {
            auto mod = mod_info();
            bss_end = mod.bss_end;
            auto dyn_seg = dynamic_seg();
            ret.push_back({
                ".dynamic",
                SHT_DYNAMIC, SHF_WRITE | SHF_ALLOC,
                dyn_seg.addr, dyn_seg.size,
                dynstr_idx, 0
            });
            if (mod.bss_start) {
                ret.push_back({
                    ".bss",
                    SHT_NOBITS, SHF_WRITE | SHF_ALLOC,
                    mod.bss_start, mod.bss_end - mod.bss_start,
                    0, 0
                });
            }
            if (mod.eh_frame_hdr_start) {
                ret.push_back({
                    ".eh_frame_hdr",
                    SHT_PROGBITS, SHF_ALLOC,
                    mod.eh_frame_hdr_start, mod.eh_frame_hdr_end - mod.eh_frame_hdr_start,
                    0, 0
                });
                auto eh_frame_addr = mod.eh_frame_hdr_start + 4 + read_data<uint32_t>(mod.eh_frame_hdr_start + 4);
                auto eh_frame_end = eh_frame_addr;
                uint32_t frame_len;
                do {
                    frame_len = read_data<uint32_t>(eh_frame_end);
                    eh_frame_end += frame_len + 4;
                } while (frame_len);
                ret.push_back({
                    ".eh_frame",
                    SHT_PROGBITS, SHF_ALLOC,
                    eh_frame_addr, eh_frame_end - eh_frame_addr,
                    0, 0
                });
            }
            auto dyn = dynamic();
            if (dyn[DT_PLTGOT]) {
                got_idx = ret.size();
                // 24 is a dummy size
                // it's not possible to know the size of the .got reliably
                ret.push_back({
                    ".got",
                    SHT_PROGBITS, SHF_ALLOC | SHF_WRITE,
                    dyn[DT_PLTGOT], 24,
                    0, 0
                });
            }
            if (dyn[DT_RELASZ]) {
                ret.push_back({
                    ".rela.dyn",
                    SHT_RELA, SHF_ALLOC,
                    dyn[DT_RELA], dyn[DT_RELASZ],
                    dynsym_idx, 0
                });
            }
            if (dyn[DT_RELSZ]) {
                ret.push_back({
                    ".rel.dyn",
                    SHT_REL, SHF_ALLOC,
                    dyn[DT_REL], dyn[DT_RELSZ],
                    dynsym_idx, 0
                });
            }
            if (dyn[DT_INIT_ARRAYSZ]) {
                ret.push_back({
                    ".init_array",
                    SHT_INIT_ARRAY, SHF_ALLOC,
                    dyn[DT_INIT_ARRAY], dyn[DT_INIT_ARRAYSZ],
                    0, 0
                });
            }
            if (dyn[DT_FINI_ARRAYSZ]) {
                ret.push_back({
                    ".fini_array",
                    SHT_FINI_ARRAY, SHF_ALLOC,
                    dyn[DT_FINI_ARRAY], dyn[DT_FINI_ARRAYSZ],
                    0, 0
                });
            }
            if (dyn[DT_HASH]) {
                auto hheader = read_data<std::pair<uint32_t, uint32_t>>((uint32_t)dyn[DT_HASH]);
                ret.push_back({
                    ".hash",
                    SHT_HASH, SHF_ALLOC,
                    dyn[DT_HASH], (hheader.first + hheader.second) * 4 + 8,
                    dynsym_idx, 0
                });
            }
            if (dyn[DT_GNU_HASH]) {
                auto hheader = read_data<GNUHashHeader>((uint32_t)dyn[DT_GNU_HASH]);
                uint32_t symcount = dynsym.size / 0x18;
                ret.push_back({
                    ".gnu.hash",
                    SHT_GNU_HASH, SHF_ALLOC,
                    dyn[DT_GNU_HASH], sizeof(GNUHashHeader) + hheader.bloom_size * 8 + hheader.nbuckets * 4 + (symcount - hheader.symoffset) * 4,
                    dynsym_idx, 0
                });
            }
            if (dyn[DT_PLTRELSZ]) {
                ret.push_back({
                    dyn[DT_PLTREL] == DT_RELA ? ".rela.plt" : ".rel.plt",
                    (uint32_t)(dyn[DT_PLTREL] == DT_RELA ? SHT_RELA : SHT_REL), SHF_ALLOC | SHF_INFO_LINK,
                    dyn[DT_JMPREL], dyn[DT_PLTRELSZ],
                    dynsym_idx, got_idx
                });
                // DT_JMPREL is guaranteed to only have relocations in the .got
                // So we can resize the .got accordingly.
                uint32_t maxrel = ret[got_idx].addr + 24;
                if (dyn[DT_PLTREL] == DT_RELA) {
                    for(const auto& rel: read_arr<ELFRela>((uint32_t)dyn[DT_JMPREL], (uint32_t)dyn[DT_PLTRELSZ] / sizeof(ELFRela))) {
                        if (maxrel < rel.offset) maxrel = rel.offset;
                    }
                } else {
                    for(const auto& rel: read_arr<ELFRel>((uint32_t)dyn[DT_JMPREL], (uint32_t)dyn[DT_PLTRELSZ] / sizeof(ELFRel))) {
                        if (maxrel < rel.offset) maxrel = rel.offset;
                    }
                }
                ret[got_idx].size = maxrel - ret[got_idx].addr;
            }
            for (auto &[tag, val]: dyn) {
                if (known_dynamic.find(tag) == known_dynamic.end()) {
                    printf("unknown dynamic tag %08llX\n", tag);
                }
            }
        }
        // now that all .dynamic-related sections have been found, add in .text/.rodata/.data sections in the missing space
        std::vector<std::pair<uint32_t, uint32_t>> filled;
        for (int i = 1; i < ret.size(); i++) filled.push_back({ret[i].addr, ret[i].addr + ret[i].size});
        std::sort(filled.begin(), filled.end(), [](const auto& l, const auto& r) { return l.first < r.first; });
        int fidx = 0;
        uint32_t segment_counter = 0;
        for(int seg = 0; seg < 3; seg++) {
            segment_counter = 0;
            NXOSegment pseg;
            std::string segname;
            switch(seg) {
                case 0: pseg = text_seg; segname = ".text"; break;
                case 1: pseg = ro_seg; segname = ".rodata"; break;
                case 2: pseg = data_seg; pseg.size = bss_end - data_seg.addr; segname = ".data"; break;
            }
            uint32_t last_filled = pseg.addr;
            uint32_t flags = seg == 0 ? SHF_ALLOC | SHF_EXECINSTR : seg == 1 ? SHF_ALLOC : SHF_ALLOC | SHF_WRITE;
            while(fidx < filled.size() && pseg.contains(filled[fidx].first, filled[fidx].second - filled[fidx].first)) {
                // need to fill space before this section
                if (last_filled < filled[fidx].first) {
                    printf("LEAD %08X %08X %08X\n", last_filled, filled[fidx].first, filled[fidx].second);
                    ret.push_back({
                        segment_counter > 0 ? segname + std::to_string(segment_counter) : segname,
                        SHT_PROGBITS, flags,
                        last_filled, filled[fidx].first - last_filled,
                        0, 0
                    });
                    segment_counter++;
                }
                last_filled = filled[fidx].second;
                fidx++;
            }
            if (last_filled < pseg.addr + pseg.size) {
                printf("TRAIL %08X %08X %08X\n", last_filled, pseg.addr, pseg.size);
                ret.push_back({
                    segment_counter > 0 ? segname + std::to_string(segment_counter) : segname,
                    SHT_PROGBITS, flags,
                    last_filled, pseg.addr + pseg.size - last_filled,
                    0, 0
                });
            }
        }
        return ret;

    }
};