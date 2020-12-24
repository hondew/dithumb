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

ElfDisassembler::ElfDisassembler(const elf::elf &elf_file) :
    m_valid{true},
    m_elf_file{&elf_file},
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

// Need to get the correct section index...
int
ElfDisassembler::getSectionIndex(const elf::section &section) const {
    int index = 0;
    for (auto &sec : m_elf_file->sections()) {
        if (sec.get_hdr().addr == section.get_hdr().addr 
        && sec.get_hdr().offset == section.get_hdr().offset) {
            return index;
        }
        ++index;
    }
    return -1;
}

// Same as func below but uses our data structs
void
ElfDisassembler::disassembleFuncs(const elf::section &sec) {
    // TODO: Make these static const constants for ElfDisassembler
    auto thumb_prelude = "thumb_func_start";
    auto arm_prelude = "arm_func_start";

    csh handle;
    initializeCapstone(&handle);

    cs_insn *inst;
    inst = cs_malloc(handle);
    BCInst instr(inst);

    size_t start_addr = sec.get_hdr().addr;
    size_t last_addr = start_addr + sec.get_hdr().size;
    const uint8_t *code_ptr = (const uint8_t *) sec.data();

    auto funcs = symbolsBySection[getSectionIndex(sec)];
    auto arm_syms = armSymbolsBySection[getSectionIndex(sec)];

    // size_t address = 0;
    // int index = 0;
    // auto mode = ARMCodeSymbol::kUnspecified;
    // for (auto &func : funcs) { 
    //     // Check if mode is specified or changed
    //     auto arm_sym = getSymbolAtOffset(arm_syms, address);
    //     if (arm_sym != NULL) {
    //         mode = ARMCodeSymbolStrings::CodeSymbol(arm_sym->symbol_name);
    //     }

    //     if (mode == ARMCodeSymbol::kData) {
    //         // Figure out size of data. Load into a buffer. Pretty print it. Go to next address.
    //     }

    //     auto prelude = (mode == ARMCodeSymbol::kARM) ? arm_prelude : thumb_prelude;
    //     printf("\n\t%s %s\n", prelude, func.symbol_name.c_str());
    //     printf("%s:\n", func.symbol_name.c_str());

    //     // Get function size
    //     auto func_end = (index < funcs.size() - 1) ? funcs[index + 1].symbol_value : last_addr;
    //     auto size = func_end - funcs[index].symbol_value;

    //     if (mode == ARMCodeSymbol::kARM)    // If we don't need `mode` for anything else, we can just place this in mode switch above 
    //         cs_option(handle, CS_OPT_MODE, CS_MODE_ARM);
    //     else
    //         cs_option(handle, CS_OPT_MODE, CS_MODE_THUMB);
    //     while (cs_disasm_iter(handle, &code_ptr, &size, &address, inst)) {
    //         printInst(handle, inst);
    //     }

    //     address += size;
    //     ++index;
    // }
    for (auto &func : funcs) {
        printf("Func: %s, offset: %x\n", func.symbol_name.c_str(), func.symbol_value);
    }
    for (auto &arm_sym : arm_syms) {
        printf("Sym: %s, offset: %x\n", arm_sym.symbol_name.c_str(), arm_sym.symbol_value);
    }

    size_t address = start_addr;
    size_t next_func_addr, next_mode_addr, next_data_addr;
    auto mode = ARMCodeSymbol::kUnspecified;
    printf("Start addr: %x, last addr: %x\n", start_addr, last_addr);
    while (address < last_addr) {
        printf("\nPiplup! Current address: %x\n", address);
        consumeUntilOffset(funcs, address); // Possibly have to pass a reference
        consumeUntilOffset(arm_syms, address);

        symbol_t * func = NULL;
        symbol_t * arm_sym = NULL;
        if (!funcs.empty()) {
            func = &funcs.front();
            printf("Func: %s, offset: %x\n", func->symbol_name.c_str(), func->symbol_value);
        }
        if (!arm_syms.empty()) {
            arm_sym = &arm_syms.front();
            printf("Arm_sym: %s, offset: %x\n", arm_sym->symbol_name.c_str(), arm_sym->symbol_value);
        }
        // If symbol is for current address
        if (arm_sym && arm_sym->symbol_value == address) {
            // ?? What if symbol is $b? Does this mess up thumb/arm? Probably best to preprocess $b's out
            mode = ARMCodeSymbolStrings::CodeSymbol(arm_sym->symbol_name);
            // TODO: Set option mode!!
        }
        if (func && func->symbol_value == address) {
            auto prelude = (mode == ARMCodeSymbol::kARM) ? arm_prelude : thumb_prelude;
            printf("\n\t%s %s\n", prelude, func->symbol_name.c_str());
            printf("%s:\n", func->symbol_name.c_str());
        }

        symbol_t func_sym, mode_sym, data_sym;
        next_func_addr = next_mode_addr = next_data_addr = last_addr;
        if (nextFuncSym(funcs, address, &func_sym)) {
            next_func_addr = func_sym.symbol_value;
        }
        if (nextModeSym(arm_syms, address, &func_sym)) {
            next_mode_addr = func_sym.symbol_value;
        }
        if (nextDataSym(arm_syms, address, &data_sym)) {
            next_data_addr = data_sym.symbol_value;
        }
        printf("Next func: %x\n", next_func_addr);
        printf("Next mode: %x\n", next_mode_addr);
        printf("Next data: %x\n", next_data_addr);
        
        auto next_address = std::min({next_func_addr, next_mode_addr, next_data_addr});
        auto size = next_address - address;
        printf("Size: %x\n", size);
        if (mode == ARMCodeSymbol::kData) {
            printData(&code_ptr, size, address);
            code_ptr += size;
        } else {
            while (cs_disasm_iter(handle, &code_ptr, &size, &address, inst)) {
                printInst(handle, inst);
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
            printInst(handle, inst);
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

const symbol_t *
ElfDisassembler::getSymbolAtOffset(std::vector<symbol_t> syms, int offset) {
    for (auto &sym :syms) {
        if (sym.symbol_value == offset) {
            return &sym;
        }
    }
    return NULL;
}

void
ElfDisassembler::filterArmSymbols() {
    for(auto it = symbols.begin(); it != symbols.end();) {
        auto sym = *it;
        if (sym.symbol_name == ARMCodeSymbolStrings::kThumb() 
        || sym.symbol_name == ARMCodeSymbolStrings::kARM() 
        || sym.symbol_name == ARMCodeSymbolStrings::kData()
        || sym.symbol_name == ARMCodeSymbolStrings::kBranch()) {
            arm_symbols.push_back(sym);
            it = symbols.erase(it);
        } else {
            ++it;
        }
    }
}

void
ElfDisassembler::filterElfSymbols() {
    for (auto it = symbols.begin(); it != symbols.end();) {
        auto sym = *it;
        if (sym.symbol_type == "SECTION" || sym.symbol_type == "FILE" || sym.symbol_type == "COMMON") {
            elf_symbols.push_back(sym);
            it = symbols.erase(it);
        } else {
            ++it;
        }
    }
}


bool
ElfDisassembler::symbolCompareByOffset(symbol_t a, symbol_t b) {
    return a.symbol_value < b.symbol_value; 
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
ElfDisassembler::nextFuncSym(std::deque<symbol_t> symbols, size_t offset, symbol_t *dest) {
    for (auto it = symbols.begin(); it != symbols.end(); ++it) {
        if (it->symbol_value > offset) {
            *dest = *it;
            return true;
        }
    }
    return false;
}

bool
ElfDisassembler::nextModeSym(std::deque<symbol_t> symbols, size_t offset, symbol_t *dest) {
    for (auto it = symbols.begin(); it != symbols.end(); ++it) {
        if (it->symbol_value <= offset)
            continue;
        if (it->symbol_name == ARMCodeSymbolStrings::kARM() 
        || it->symbol_name == ARMCodeSymbolStrings::kThumb()) {
            *dest = *it;
            return true;
        }
    }
    return false;
}

// Find first data sym after offset
bool
ElfDisassembler::nextDataSym(std::deque<symbol_t> symbols, size_t offset, symbol_t *dest) {
    for (auto it = symbols.begin(); it != symbols.end(); ++it) {
        if (it->symbol_value > offset && it->symbol_name == ARMCodeSymbolStrings::kData()) {
            *dest = *it;
            return true;
        }
    }
    return false;
}

void
ElfDisassembler::prepareSymbols() {
    filterArmSymbols();
    filterElfSymbols();
    symbolsBySection = symbolQueuesBySection(symbols);
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


// Given vector of symbols, and vector of sections, should create a vector of
// relocation_t.
// Must call parseSymbols() first
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
            
            rel.relocation_plt_address = plt_vma_address + (i + 1) * plt_entry_size;
            rel.relocation_section_name = sec.get_name();
            
            relocations.push_back(rel);
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
        if (sec.is_alloc() && sec.is_exec()) {
            disassembleFuncs(sec);
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

const relocation_t *
ElfDisassembler::relocationAtOffset(std::intptr_t offset) const {
    for (auto &rel : relocations) {
        if (rel.relocation_offset == offset) {
            return &rel;
        }
    }
    return nullptr;
}

void 
ElfDisassembler::printData(const uint8_t **code, size_t size, size_t address) {
    // Maybe load the data into a fixed size buffer, if this is built in
    // with load().
    printf("hi, i'm data\n");
}

void 
ElfDisassembler::printInst(const csh &handle, cs_insn *inst) {
    if (isFunctionCall(inst)) {
        if (inst->detail->arm.operands[0].imm == inst->address) {
            // Use relocation table
            auto rel = relocationAtOffset(inst->detail->arm.operands[0].imm);
            if (rel != NULL) {
                printf("0x%" PRIx64 ":\t%s\t\t%s\n",
                    inst->address, inst->mnemonic, rel->relocation_symbol_name.c_str());
            }
        } else {
            // Use symbol table
            auto sym = getSymbolAtOffset(symbols, inst->detail->arm.operands[0].imm);
            if (sym != NULL) {
                printf("0x%" PRIx64 ":\t%s\t\t%s\n",
                       inst->address, inst->mnemonic, sym->symbol_name.c_str());
            }
        }
    } else {
        printf("0x%" PRIx64 ":\t%s\t\t%s\n",
            inst->address, inst->mnemonic, inst->op_str);
    }

//    printf("0x%" PRIx64 ":\t%s\t\t%s // insn-ID: %u, insn-mnem: %s\n",
//           inst->address, inst->mnemonic, inst->op_str,
//           inst->id, cs_insn_name(handle, inst->id));

    // print implicit registers used by this instruction
//    detail = inst->detail;
//
//    if (detail == NULL) return;
//
//    if (detail->regs_read_count > 0) {
//        printf("\tImplicit registers read: ");
//        for (n = 0; n < detail->regs_read_count; n++) {
//            printf("%s ", cs_reg_name(handle, detail->regs_read[n]));
//        }
//        printf("\n");
//    }
//
//    // print implicit registers modified by this instruction
//    if (detail->regs_write_count > 0) {
//        printf("\tImplicit registers modified: ");
//        for (n = 0; n < detail->regs_write_count; n++) {
//            printf("%s ", cs_reg_name(handle, detail->regs_write[n]));
//        }
//        printf("\n");
//    }
//
//    // print the groups this instruction belong to
//    if (detail->groups_count > 0) {
//        printf("\tThis instruction belongs to groups: ");
//        for (n = 0; n < detail->groups_count; n++) {
//            printf("%s ", cs_group_name(handle, detail->groups[n]));
//        }
//        printf("\n");
//    }
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
