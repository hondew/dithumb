//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under the MIT License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#include "ElfDisassembler.h"
#include "BCInst.h"
#include <inttypes.h>
#include <algorithm>

namespace disasm {

const char * kThumbPrelude = "thumb_func_start";
const char * kArmPrelude = "arm_func_start";

class ARMCodeSymbolStrings {
public:
    static std::string
    kThumb() { return "$t"; }

    static std::string
    kARM() { return "$a"; }

    static std::string
    kData() { return "$d"; }

    static std::string
    kBranch() { return "$b"; }

    static ARMCodeSymbol 
    CodeSymbol(std::string code) {
        if (code == kThumb()) {
            return ARMCodeSymbol::kThumb;
        } else if (code == kARM()) {
            return ARMCodeSymbol::kARM;
        } else if (code == kData()) {
            return ARMCodeSymbol::kData;
        } else if (code == kBranch()) {
            return ARMCodeSymbol::kBranch;
        } else {
            return ARMCodeSymbol::kUnspecified;
        }
    }
};

ElfDisassembler::ElfDisassembler() : m_valid{false} { }

ElfDisassembler::ElfDisassembler(const elf::elf &elf_file, uint column_width) :
    m_valid{true},
    m_elf_file{&elf_file},
    dataColumnWidth{column_width},
    m_config{} { }

void
ElfDisassembler::print_string_hex(unsigned char *str, size_t len) const {
    unsigned char *c;

    printf("Code: ");
    for (c = str; c < str + len; c++) {
        printf("0x%02x ", *c & 0xff);
    }
    printf("\n");
}

void inline
ElfDisassembler::initializeCapstone(csh *handle) const {
    cs_err err_no;
    err_no = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, handle);
    if (err_no) {
        throw std::runtime_error("Failed on cs_open() "
                                     "with error returned:" + err_no);
    }

    cs_option(*handle, CS_OPT_DETAIL, CS_OPT_ON);
}

int
ElfDisassembler::getSectionIndex(const elf::section &section) const {
    int index = 0;
    for (auto &sec : m_elf_file->sections()) {
        if (sec.get_hdr().addr  == section.get_hdr().addr 
        && sec.get_hdr().offset == section.get_hdr().offset
        && sec.get_hdr().size   == section.get_hdr().size
        && sec.get_hdr().type   == section.get_hdr().type
        && sec.get_hdr().name   == section.get_hdr().name) {
            return index;
        }
        ++index;
    }
    return -1;
}

void
ElfDisassembler::disassembleBss(const elf::section &sec) {
    auto start_addr = sec.get_hdr().addr;
    auto last_addr = start_addr + sec.get_hdr().size;
    const uint8_t *data_ptr = (const uint8_t *) sec.data();

    auto syms = symbolsBySection[getSectionIndex(sec)];

    symbol_t next_sym;
    auto address = start_addr;
    while (address < last_addr) {
        consumeUntilOffset(syms, address);
        printf("\n\t.global %s\n%s:\n", 
            syms.front().symbol_name.c_str(), syms.front().symbol_name.c_str());

        auto next_addr = last_addr;
        if (nextSym(syms, address, &next_sym)) {
            next_addr = next_sym.symbol_value;
        }

        auto size = next_addr - address;
        printf("\t.space 0x%x\n", size);
        address = next_addr;
    }
}

void
ElfDisassembler::disassembleData(const elf::section &sec) {
    auto start_addr = sec.get_hdr().addr;
    auto last_addr = start_addr + sec.get_hdr().size;
    const uint8_t *data_ptr = (const uint8_t *) sec.data();

    auto syms = symbolsBySection[getSectionIndex(sec)];

    // for (auto sym : syms) {
    //     printf("data symbol: %s, offset: %x\n", sym.symbol_name.c_str(), sym.symbol_value);
    // }

    symbol_t next_sym;
    auto address = start_addr;
    while (address < last_addr) {
        consumeUntilOffset(syms, address);
        printf("\n\t.global %s\n%s:\n", 
            syms.front().symbol_name.c_str(), syms.front().symbol_name.c_str());

        auto next_addr = last_addr;
        if (nextSym(syms, address, &next_sym)) {
            next_addr = next_sym.symbol_value;
        }
        printDataDump(&data_ptr, address, next_addr - address, getSectionIndex(sec));
        address = next_addr;
    }
}

void
ElfDisassembler::disassembleDataSection(const elf::section &sec) {
    printf("\n\t.section %s\n", sec.get_name().c_str());
    if (sec.get_name() == ".bss") {
        disassembleBss(sec);
    } else {
        disassembleData(sec);
    }
}

void
ElfDisassembler::disassembleFuncs(const elf::section &sec) {
    csh handle;
    initializeCapstone(&handle);

    cs_insn *inst;
    inst = cs_malloc(handle);
    BCInst instr(inst);

    size_t start_addr = sec.get_hdr().addr;
    size_t last_addr = start_addr + sec.get_hdr().size;
    const uint8_t *code_ptr = (const uint8_t *) sec.data();

    auto funcs = symbolsBySection[getSectionIndex(sec)];
    auto data_syms = dataSymbolsBySection[getSectionIndex(sec)];
    auto mode_syms = modeSymbolsBySection[getSectionIndex(sec)];

    for (auto &func : funcs) {
        printf("Func: %s, offset: %x\n", func.symbol_name.c_str(), func.symbol_value);
    }
    for (auto &data_sym : data_syms) {
        printf("Data: %s, offset: %x\n", data_sym.symbol_name.c_str(), data_sym.symbol_value);
    }
    for (auto &mode_sym : mode_syms) {
        printf("Mode: %s, offset: %x\n", mode_sym.symbol_name.c_str(), mode_sym.symbol_value);
    }

    size_t address = start_addr;
    size_t next_func_addr, next_mode_addr, next_data_addr;
    symbol_t func_sym, mode_sym, data_sym;
    auto mode = ARMCodeSymbol::kUnspecified;
    printf("Start addr: %x, last addr: %x\n", start_addr, last_addr);
    printf("\n\t.text\n");
    while (address < last_addr) {
        printf("\nPiplup! Current address: %x\n", address);
        consumeUntilOffset(funcs, address);
        consumeUntilOffset(data_syms, address);
        consumeUntilOffset(mode_syms, address);

        // If symbol is for current address
        if (!mode_syms.empty() && mode_syms.front().symbol_value == address) {
            mode = ARMCodeSymbolStrings::CodeSymbol(mode_syms.front().symbol_name);
            cs_option(handle, CS_OPT_MODE, (mode == ARMCodeSymbol::kARM) ? CS_MODE_ARM : CS_MODE_THUMB);
        }
        if (!funcs.empty() && funcs.front().symbol_value == address) {
            auto prelude = (mode == ARMCodeSymbol::kARM) ? kArmPrelude : kThumbPrelude;
            printf("\n\t%s %s\n", prelude, funcs.front().symbol_name.c_str());
            printf("%s:\n", funcs.front().symbol_name.c_str());
        }

        next_func_addr = next_mode_addr = next_data_addr = last_addr;
        if (nextSym(funcs, address, &func_sym)) {
            next_func_addr = func_sym.symbol_value;
        }
        if (nextSym(mode_syms, address, &mode_sym)) {
            next_mode_addr = mode_sym.symbol_value;
        }
        if (nextSym(data_syms, address, &data_sym)) {
            next_data_addr = data_sym.symbol_value;
        }
        printf("Next func: %x\n", next_func_addr);
        printf("Next mode: %x\n", next_mode_addr);
        printf("Next data: %x\n", next_data_addr);
        
        auto next_address = std::min({next_func_addr, next_mode_addr, next_data_addr});
        auto size = next_address - address;
        printf("Size: %x\n", size);
        if (!data_syms.empty() && data_syms.front().symbol_value == address) {
            printDataPool(&code_ptr, address, size, getSectionIndex(sec));
        } else {
            while (cs_disasm_iter(handle, &code_ptr, &size, &address, inst)) {
                printInst(handle, inst, getSectionIndex(sec));
            }
        }

        address += size;
    }
}

void
ElfDisassembler::disassembleSectionUsingSymbols(const elf::section &sec) {
    auto symbols = getCodeSymbolsForSection(sec);
//    printf("Symbols size is %lu \n", symbols.size());
//
//    for (auto& symbol : symbols) {
//        printf("Type %d, Addrd, 0x%#x \n", symbol.second, symbol.first);
//    }
    csh handle;

    initializeCapstone(&handle);
    size_t start_addr = sec.get_hdr().addr;
    size_t last_addr = start_addr + sec.get_hdr().size;
    const uint8_t *code_ptr = (const uint8_t *) sec.data();
    cs_insn *inst;

    printf("Start addr: %x, Last addr: %x\n", start_addr, last_addr);

    inst = cs_malloc(handle);
    BCInst instr(inst);
    printf("***********************************\n");
    printf("Section name: %s\n", sec.get_name().c_str());

    // We assume that symbols are ordered by their address.
    size_t index = 0;
    size_t address = 0;
    size_t size = 0;
    size_t instruction_count = 0;
    size_t basic_block_count = 0;
    size_t direct_branch_count = 0;
    for (auto &symbol : symbols) {
        index++;
        if (symbol.second == ARMCodeSymbol::kData) {
            if (index < symbols.size())
                // adjust code_ptr to start of next symbol.
                code_ptr += (symbols[index].first - symbol.first);
            continue;
        }
        address = symbol.first;
        if (index < symbols.size())
            size = symbols[index].first - symbol.first;
        else
            size = last_addr - symbol.first;

        if (symbol.second == ARMCodeSymbol::kARM)
            cs_option(handle, CS_OPT_MODE, CS_MODE_ARM);
        else
            // We assume that the value of code symbol type is strictly
            // either Data, ARM, or Thumb.
            cs_option(handle, CS_OPT_MODE, CS_MODE_THUMB);

        while (cs_disasm_iter(handle, &code_ptr, &size, &address, inst)) {
            printInst(handle, inst, getSectionIndex(sec));
            instruction_count++;
            if (isBranch(inst)) {
                // printf("Basic block end.\n");
                // printf("***********************************\n");
                basic_block_count++;
                if (isDirectBranch(inst)) {
                    direct_branch_count++;
                }
            }
        }
    }
    // printf("Instruction count: %lu\nBasic Block count: %lu\n"
    //            "Direct jumps: %lu (%2.2f \%%)\nIndirect jumps:%lu (%2.2f \%%)\n",
    //        instruction_count,
    //        basic_block_count,
    //        direct_branch_count,
    //        ((double)direct_branch_count * 100) / (double)basic_block_count,
    //        basic_block_count - direct_branch_count,
    //        (double)((basic_block_count - direct_branch_count) * 100
    //            / basic_block_count));
    cs_close(&handle);
}

const elf::section &
ElfDisassembler::findSectionbyName(std::string sec_name) const {
    for (auto &sec : m_elf_file->sections()) {
        if (sec.get_name() == sec_name) {
            return sec;
        }
    }
}

std::vector<symbol_t>
ElfDisassembler::filterDataSymbols(std::vector<symbol_t> &symbols) {
    std::vector<symbol_t> filtered;
    for(auto it = symbols.begin(); it != symbols.end();) {
        auto sym = *it;
        if (sym.symbol_name == ARMCodeSymbolStrings::kData()) {
            filtered.push_back(sym);
            it = symbols.erase(it);
        } else {
            ++it;
        }
    }
    return filtered;
}

std::vector<symbol_t>
ElfDisassembler::filterModeSymbols(std::vector<symbol_t> &symbols) {
    std::vector<symbol_t> filtered;
    for(auto it = symbols.begin(); it != symbols.end();) {
        auto sym = *it;
        if (sym.symbol_name == ARMCodeSymbolStrings::kThumb() 
        || sym.symbol_name == ARMCodeSymbolStrings::kARM()) {
            filtered.push_back(sym);
            it = symbols.erase(it);
        } else {
            ++it;
        }
    }
    return filtered;
}

std::vector<symbol_t>
ElfDisassembler::filterArmSymbols(std::vector<symbol_t> &symbols) {
    std::vector<symbol_t> filtered;
    for(auto it = symbols.begin(); it != symbols.end();) {
        auto sym = *it;
        if (sym.symbol_name == ARMCodeSymbolStrings::kBranch()) {
            filtered.push_back(sym);
            it = symbols.erase(it);
        } else {
            ++it;
        }
    }
    return filtered;
}

std::vector<symbol_t>
ElfDisassembler::filterElfSymbols(std::vector<symbol_t> &symbols) {
    std::vector<symbol_t> filtered;
    for (auto it = symbols.begin(); it != symbols.end();) {
        auto sym = *it;
        if (sym.symbol_type == "SECTION" || sym.symbol_type == "FILE" || sym.symbol_type == "COMMON") {
            filtered.push_back(sym);
            it = symbols.erase(it);
        } else {
            ++it;
        }
    }
    return filtered;
}

bool
ElfDisassembler::symbolCompareByOffset(symbol_t a, symbol_t b) {
    return a.symbol_value < b.symbol_value; 
}

bool
ElfDisassembler::relocationCompareByOffset(relocation_t a, relocation_t b) {
    return a.relocation_offset < b.relocation_offset; 
}

// Return a map[section]deque<symbols>, where the deque is sorted by offset.
std::map<int, std::deque<symbol_t>>
ElfDisassembler::symbolQueuesBySection(std::vector<symbol_t> symbols) {
    auto symsBySection = groupSymbolsBySection(symbols);

    // Sort each vector by offset
    for (auto &[section_id, syms] : symsBySection) {
        std::sort(syms.begin(), syms.end(), symbolCompareByOffset);
    }

    std::map<int, std::deque<symbol_t>> symQueuesBySection;
    for (auto &[section_id, syms] : symsBySection) {
        for (auto sym : syms) {
            symQueuesBySection[section_id].push_back(sym);
        }
    }
    return symQueuesBySection;
}

std::map<int, std::vector<symbol_t>>
ElfDisassembler::groupSymbolsBySection(std::vector<symbol_t> symbols) {
    std::map<int, std::vector<symbol_t>> symsBySection;
    for (auto &sym : symbols) {
        if (sym.symbol_index == SHN_UNDEF) 
            continue;
        symsBySection[sym.symbol_index].push_back(sym);
    }
    return symsBySection;
}

void
ElfDisassembler::consumeUntilOffset(std::deque<symbol_t> &symbols, size_t offset) {
    while (!symbols.empty() && symbols.front().symbol_value < offset) {
        symbols.pop_front();
    }
}

bool
ElfDisassembler::nextSym(std::deque<symbol_t> symbols, size_t offset, symbol_t *dest) {
    for (auto it = symbols.begin(); it != symbols.end(); ++it) {
        if (it->symbol_value > offset) {
            *dest = *it;
            return true;
        }
    }
    return false;
}

void
ElfDisassembler::prepareRelocations() {
    // Sort each vector<relocation_t> by offset
    for (auto &[section_id, rels] : relocationsBySection) {
        std::sort(rels.begin(), rels.end(), relocationCompareByOffset);
    }
}

void
ElfDisassembler::prepareSymbols() {
    printf("Printing symbols before filtering:\n");
    for (auto sym : symbols) {
        printf("Symbol: %s, offset: %x\n", sym.symbol_name.c_str(), sym.symbol_value);
    }

    data_symbols = filterDataSymbols(symbols);
    mode_symbols = filterModeSymbols(symbols);
    arm_symbols = filterArmSymbols(symbols);
    elf_symbols = filterElfSymbols(symbols);
    
    symbolsBySection = symbolQueuesBySection(symbols);
    dataSymbolsBySection = symbolQueuesBySection(data_symbols);
    modeSymbolsBySection = symbolQueuesBySection(mode_symbols);
    armSymbolsBySection = symbolQueuesBySection(arm_symbols);
}

void
ElfDisassembler::parseSymbols() {
    // get strtab
    char *sh_strtab_p = nullptr;
    for (auto &sec : m_elf_file->sections()) {
        if (sec.get_hdr().type == elf::sht::strtab && sec.get_name() == ".strtab") {
            sh_strtab_p = (char *)sec.data();
            break;
        }
    }

    // get dynstr
    char *sh_dynstr_p = nullptr;
    for (auto &sec : m_elf_file->sections()) {
        if (sec.get_hdr().type == elf::sht::strtab && sec.get_name() == ".dynstr") {
            sh_dynstr_p = (char *)sec.data();
            break;
        }
    }

    for (auto &sec : m_elf_file->sections()) {
        if ((sec.get_hdr().type != elf::sht::symtab) && (sec.get_hdr().type != elf::sht::dynsym))
            continue;

        auto total_syms = sec.size() / sizeof(Elf32_Sym);
        auto syms_data = (Elf32_Sym*)sec.data();

        for (int i = 0; i < total_syms; ++i) {
            symbol_t symbol;
            symbol.symbol_num       = i;
            symbol.symbol_value     = syms_data[i].st_value;
            symbol.symbol_size      = syms_data[i].st_size;
            symbol.symbol_type      = get_symbol_type(syms_data[i].st_info);
            symbol.symbol_index     = syms_data[i].st_shndx;
            symbol.symbol_section   = sec.get_name();
            
            if(sec.get_hdr().type == elf::sht::symtab)
                symbol.symbol_name = std::string(sh_strtab_p + syms_data[i].st_name);
            
            if(sec.get_hdr().type == elf::sht::dynsym)
                symbol.symbol_name = std::string(sh_dynstr_p + syms_data[i].st_name);
            
            symbols.push_back(symbol);
        }
    }
}

// Assumes relocations are sorted by offset
bool
ElfDisassembler::nextRel(std::vector<relocation_t> &rels, size_t offset, relocation_t *dest) {
    for (auto it = rels.begin(); it != rels.end(); ++it) {
        if (it->relocation_offset > offset) {
            *dest = *it;
            return true;
        }
    }
    return false;
}

// Given vector of symbols, and vector of sections, should create a vector of
// relocation_t.
// Must call parseSymbols() first
// We will index relocations by the sections they correspond to
void
ElfDisassembler::parseRelocations() {
    int  plt_entry_size = 0;
    long plt_vma_address = 0;

    for (auto &sec : m_elf_file->sections()) {
        if(sec.get_name() == ".plt") {
          plt_entry_size = sec.get_hdr().entsize;
          plt_vma_address = sec.get_hdr().addr;
          break;
        }
    }

    for (auto &sec : m_elf_file->sections()) {

        if(sec.get_hdr().type != elf::sht::rela) 
            continue;

        auto total_relas = sec.size() / sizeof(Elf32_Rela);
        auto relas_data  = (Elf32_Rela*)(sec.data());

        for (int i = 0; i < total_relas; ++i) {
            relocation_t rel;
            rel.relocation_offset = static_cast<std::intptr_t>(relas_data[i].r_offset);
            rel.relocation_info   = static_cast<std::intptr_t>(relas_data[i].r_info);
            rel.relocation_symbol_value = \
                get_rel_symbol_value(relas_data[i].r_info, symbols);
            rel.relocation_symbol_name  = \
                get_rel_symbol_name(relas_data[i].r_info, symbols);
            rel.relocation_addend = relas_data[i].r_addend;
            
            rel.relocation_plt_address = plt_vma_address + (i + 1) * plt_entry_size;
            rel.relocation_section_name = sec.get_name();
            
            relocationsBySection[sec.get_hdr().info].push_back(rel);
        }
    }
    printf("Printing relocations:\n");
    for (auto &[section_id, rels] : relocationsBySection) {
        printf("Section %d:\n", section_id);
        for (auto rel : rels) {
            printf("Relocation: %s, offset: %x, addend: %x\n", 
                rel.relocation_symbol_name.c_str(), rel.relocation_offset, rel.relocation_addend);
        }
    }
}

void
ElfDisassembler::disassembleCodeUsingSymbols() {
    // Inspect contents - should be own fn
    printf("ELF sections:\n");
    for (auto &sec : m_elf_file->sections()) {
        printf("Name: %s, size: %ld\n", sec.get_name().c_str(), sec.size());
        printf("File offset for section: %lx\n", sec.get_hdr().offset);
    }
    for (auto &sec : m_elf_file->sections()) {
        printf("\n~ Disassembling section idx: %d, size: %x ~\n", getSectionIndex(sec), sec.get_hdr().size);
        if (sec.is_alloc() && sec.is_exec()) {
            disassembleFuncs(sec);
        } else if (sec.is_alloc()) {
            disassembleDataSection(sec);
        }
    }
}

bool ElfDisassembler::isDirectBranch(const cs_insn *inst) const {
    return inst->detail->arm.op_count == 1
        && inst->detail->arm.operands[0].type == ARM_OP_IMM;
}

bool ElfDisassembler::isBranch(const cs_insn *inst) const {
    if (inst->detail == NULL) return false;

    cs_detail *detail = inst->detail;
    // assuming that each instruction should belong to at least one group
    if (detail->groups[detail->groups_count - 1] == ARM_GRP_JUMP)
        return true;
    if (inst->id == ARM_INS_POP) {
        // pop accepts a register list. If pc was among them then this a branch
        for (int i = 0; i < detail->arm.op_count; ++i) {
            if (detail->arm.operands[i].reg == ARM_REG_PC) return true;
        }
    }

    if ((detail->arm.operands[0].type == ARM_OP_REG)
        && (detail->arm.operands[0].reg == ARM_REG_PC)) {
        if (inst->id == ARM_INS_STR) {
            return false;
        }
        return true;
    }
    return false;
}

bool ElfDisassembler::isFunctionCall(const cs_insn *inst) const {
    return isBranch(inst) && (inst->id == ARM_INS_BL || inst->id == ARM_INS_BLX);
}

// Return the label that the instruction refers to
bool ElfDisassembler::lookupLabel(const cs_insn *inst /*, list of labels */) const {
    return true;
}

// Extract all labels from list of instructions
void ElfDisassembler::extractLabels(std::vector<cs_insn>) const {

}

bool
ElfDisassembler::relocationAtOffset(std::intptr_t offset, int section_idx, relocation_t *dest) {
    auto relocations = relocationsBySection[section_idx];
    for (auto &rel : relocations) {
        if (rel.relocation_offset == offset) {
            *dest = rel;
            return true;
        }
    }
    return false;
}

uint8_t
ElfDisassembler::consumeByte(const uint8_t **data) {
    auto ret = *(*data);
    (*data)++;
    return ret;
}

uint16_t
ElfDisassembler::consumeShort(const uint8_t **data) {
    return (consumeByte(data) << 0
          | consumeByte(data) << 8);
}

uint32_t
ElfDisassembler::consumeWord(const uint8_t **data) {
    return (consumeByte(data) << 0
          | consumeByte(data) << 8
          | consumeByte(data) << 16
          | consumeByte(data) << 24);
}

void
ElfDisassembler::printDataRelocation(const uint8_t **data, relocation_t rel) {
    symbol_t elf_sym, internal_sym;
    auto symbol_name = rel.relocation_symbol_name;

    // Symbol defined within this object file
    if (get_rel_symbol(rel.relocation_info, elf_symbols, &elf_sym)) {
        // printf("glameow\n");
        // printf("Sym idx: %d\n", elf_sym.symbol_index);

        // Doesn't handle cases where the data points to some offset after the symbol 
        // (e.g. https://github.com/pret/pokediamond/blob/ee1f12ce06e865f47511ba200029e0afaafa4255/arm9/asm/libVCT.s#L1967-L1968).
        // Instead, we need to get the closest symbol before the address 
        // relocation_addend. If it does not line up with a symbol, add the 
        // remainder to the previous symbol.
        if (lookupSymbol(symbols, elf_sym.symbol_index, rel.relocation_addend, &internal_sym)) {
            // printf("purugly: refers to %s\n", internal_sym.symbol_name.c_str());
            symbol_name = internal_sym.symbol_name;
        }
    }
    printf("\t.word %s, sym idx: %x, addend: %x\n", 
        symbol_name.c_str(), 
        ELF32_R_SYM(rel.relocation_info),
        rel.relocation_addend);
    consumeWord(data);
}

void
ElfDisassembler::printRawBytes(const uint8_t **data, size_t size) {
    auto end = *data + size;
    auto column = 0;
    while (*data < end) {
        if (column == 0)
            printf("\t.byte");
        printf(" 0x%02X", consumeByte(data));

        auto delimiter = (column == dataColumnWidth - 1 || *data == end) ? "\n" : ",";
        printf(delimiter);
        column = (column + 1) % dataColumnWidth;
    }
}

void
ElfDisassembler::printDataDump(const uint8_t **data, size_t start_addr, size_t size, int section_idx) {
    auto start = *data;
    auto end = *data + size;
    auto last_addr = start_addr + size;
    auto relocations = relocationsBySection[section_idx];

    // printf("Relocations:\n");
    // for (auto rel : relocations) {
    //     printf("Relocation: %s, offset: %x\n", rel.relocation_symbol_name.c_str(), rel.relocation_offset);
    // }

    // Dumps data as .bytes, unless the data holds a relocation symbol
    while (*data < end) {
        auto address = start_addr + *data - start;
        relocation_t rel;
        if (relocationAtOffset(address, section_idx, &rel)) {
            printDataRelocation(data, rel);
            continue;
        }

        auto next_addr = last_addr;
        if (nextRel(relocations, address, &rel)) {
            if (rel.relocation_offset < last_addr) {
                next_addr = rel.relocation_offset;
            }
        }
        printRawBytes(data, next_addr - address);
    }
}

void
ElfDisassembler::printDataPool(const uint8_t **data, size_t start_addr, size_t size, int section_idx) {
    auto start = *data;
    auto end = *data + size;
    while (*data < end) {
        relocation_t rel;
        if (relocationAtOffset(start_addr + *data - start, section_idx, &rel)) {
            printDataRelocation(data, rel);
            continue;
        } 

        auto spacesLeft = end - *data;
        if (spacesLeft < 2) {
            printf("\t.byte 0x%02X\n", consumeByte(data));
        } else if (spacesLeft < 4) {
            printf("\t.hword 0x%04X\n", consumeShort(data));
        } else {
            printf("\t.word 0x%08X\n", consumeWord(data));
        }
    }
}

void
ElfDisassembler::printFuncCall(cs_insn *inst, int section_idx) {
    // printf("bl offset: %x\n", inst->detail->arm.operands[0].imm);

    relocation_t rel;
    symbol_t sym;
    // Try relocation table
    if (relocationAtOffset(inst->address, section_idx, &rel)) {
        printf("0x%" PRIx64 ":\t%s\t\t%s\n",
            inst->address, inst->mnemonic, rel.relocation_symbol_name.c_str());
    } 
    // Try symbol table
    else if (lookupSymbol(symbols, section_idx, inst->detail->arm.operands[0].imm, &sym)) {
        printf("0x%" PRIx64 ":\t%s\t\t%s\n",
                inst->address, inst->mnemonic, sym.symbol_name.c_str());
    }
}

// TODO: Handle branches to addresses within the object. Requires label 
// processing.
void 
ElfDisassembler::printInst(const csh &handle, cs_insn *inst, int section_idx) {
    if (isFunctionCall(inst)) {
        printFuncCall(inst, section_idx);
    } else {
        printf("0x%" PRIx64 ":\t%s\t\t%s\n",
            inst->address, inst->mnemonic, inst->op_str);
    }
}

std::vector<std::pair<size_t, ARMCodeSymbol>>
ElfDisassembler::getCodeSymbolsForSection(const elf::section &sec) const {
    std::vector<std::pair<size_t, ARMCodeSymbol>> result;

    // Check for symbol table, if none was found then
    // the instance is invalid.
    elf::section sym_sec = m_elf_file->get_section(".symtab");
    // Returning a valid section means that there was no symbol table
    //  provided in ELF file.
    if (!sym_sec.valid())
        return result;

    size_t start_addr = sec.get_hdr().addr;
    size_t end_addr = start_addr + sec.get_hdr().size;

    // The following can throw a type_mismatch exception in case
    // of corrupted symbol table in ELF.

    for (auto symbol: sym_sec.as_symtab()) {
        size_t value = symbol.get_data().value;
        // we assume that the start addr of each section is available in
        // code symbols.
        if ((start_addr <= value) && (value < end_addr)) {
            if (symbol.get_name() == ARMCodeSymbolStrings::kThumb()) {
                result.emplace_back(std::make_pair(value,
                                                   ARMCodeSymbol::kThumb));

            } else if (symbol.get_name() == ARMCodeSymbolStrings::kARM()) {
                result.emplace_back(std::make_pair(value,
                                                   ARMCodeSymbol::kARM));

            } else if (symbol.get_name() == ARMCodeSymbolStrings::kData()) {
                result.emplace_back(std::make_pair(value,
                                                   ARMCodeSymbol::kData));

            }
        }
    }
    // Symbols are not necessary sorted, this step is required to
    // avoid potential SEGEV.
    std::sort(result.begin(), result.end());
    return result;
}

bool
ElfDisassembler::isSymbolTableAvailable() {
    elf::section sym_sec = m_elf_file->get_section(".symtab");
    // Returning a invalid section means that there was no symbol table
    //  provided in ELF file.

    return sym_sec.valid();
}

std::string 
ElfDisassembler::get_symbol_type(uint8_t &sym_type) {
    switch(ELF32_ST_TYPE(sym_type)) {
        case 0: return "NOTYPE";
        case 1: return "OBJECT";
        case 2: return "FUNC";
        case 3: return "SECTION";
        case 4: return "FILE";
        case 6: return "TLS";
        case 7: return "NUM";
        case 10: return "LOOS";
        case 12: return "HIOS";
        default: return "UNKNOWN";
    }
}

// Find a symbol at the specified offset. Assumes that `syms` are all from the same section.
bool
ElfDisassembler::lookupSymbol(std::vector<symbol_t> &syms, size_t section_idx, size_t offset, symbol_t *dest) {
    for (auto &sym : syms) {
        if (sym.symbol_index == section_idx && sym.symbol_value == offset) {
            *dest = sym;
            return true;
        }
    }
    return false;
}

bool
ElfDisassembler::get_rel_symbol(uint32_t sym_idx, std::vector<symbol_t> &syms, symbol_t *dest) {
    for (auto &sym : syms) {
        if (sym.symbol_num == ELF32_R_SYM(sym_idx)) {
            *dest = sym;
            return true;
        }
    }
    return false;
}

std::intptr_t 
ElfDisassembler::get_rel_symbol_value(
                uint32_t &sym_idx, std::vector<symbol_t> &syms) {
    
    std::intptr_t sym_val = 0;
    for(auto &sym: syms) {
        if(sym.symbol_num == ELF32_R_SYM(sym_idx)) {
            sym_val = sym.symbol_value;
            break;
        }
    }
    return sym_val;
}

std::string 
ElfDisassembler::get_rel_symbol_name(
                uint32_t &sym_idx, std::vector<symbol_t> &syms) {

    std::string sym_name;
    for(auto &sym: syms) {
        if(sym.symbol_num == ELF32_R_SYM(sym_idx)) {
            sym_name = sym.symbol_name;
            break;
        }
    }
    return sym_name;
}
}
