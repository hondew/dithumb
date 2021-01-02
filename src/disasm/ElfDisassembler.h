//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under the MIT License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#pragma once
#include <deque>
#include <map>
#include "binutils/elf/elf++.hh"
#include <elf.h>
#include <capstone/capstone.h>

namespace disasm {

enum class ARMCodeSymbol: std::int16_t {
    kUnspecified = -1,
    kThumb = 1,
    kARM = 2,
    kData = 4,
    kBranch = 8
};

typedef struct {
        Elf32_Addr      r_offset;
        Elf32_Word      r_info;
        Elf32_Sword     r_addend;
} Elf32_Rela;

typedef struct {
    uint16_t symbol_index;
    std::intptr_t symbol_value;
    int symbol_num = 0, symbol_size = 0;
    std::string symbol_type, symbol_bind, symbol_visibility, symbol_name, symbol_section;      
} symbol_t;

typedef struct {
    std::intptr_t relocation_offset, relocation_info, relocation_symbol_value, relocation_addend;
    std::string   relocation_type, relocation_symbol_name, relocation_section_name;
    std::intptr_t relocation_plt_address;
} relocation_t;

/**
 * ElfDisassembler
 */
class ElfDisassembler {
public:
    /**
     * Construct a Elf Disassembler that is initially not valid.  Calling
     * methods other than valid on this results in undefined behavior.
     */
    ElfDisassembler();

    /**
     * Prepares input file for disassembly.
     * Precondition: file is a valid ELF file.
     */
    ElfDisassembler(const elf::elf& elf_file, uint columnWidth);
    virtual ~ElfDisassembler() = default;
    ElfDisassembler(const ElfDisassembler &src) = delete;
    ElfDisassembler &operator=(const ElfDisassembler &src) = delete;
    ElfDisassembler(ElfDisassembler &&src) = default;

    bool valid() const { return m_valid; }
    void parseSymbols();
    void parseRelocations();
    void prepareSymbols();
    void prepareRelocations();
    void disassembleCodeUsingSymbols();
    void disassembleCodeUsingLinearSweep() const;

    const elf::section & findSectionbyName(std::string sec_name) const;
    void print_string_hex(unsigned char *str, size_t len) const;
    bool isSymbolTableAvailable();
    
    void disassembleDataSection(const elf::section &sec);
    void disassembleFuncs(const elf::section &sec);
    void disassembleSectionUsingSymbols(const elf::section &sec);
    void disassembleSectionUsingLinearSweep(const elf::section &sec) const;

private:
    bool isBranch(const cs_insn *inst) const;
    bool isDirectBranch(const cs_insn *inst) const;
    bool isFunctionCall(const cs_insn *inst) const;
    bool lookupLabel(const cs_insn *inst) const;
    void extractLabels(std::vector<cs_insn>) const;
    bool relocationAtOffset(std::intptr_t offset, int section_idx, relocation_t *dest);
    void printInst(const csh& handle, cs_insn* inst, int section_idx);
    void printFuncCall(cs_insn *inst, int section_idx);
    void printDataPool(const uint8_t **code, size_t start_addr, size_t size, int section_idx);
    void printDataDump(const uint8_t **data, size_t start_addr, size_t size, int section_idx);
    void printRawBytes(const uint8_t **data, size_t size);

    void disassembleData(const elf::section &sec);
    void disassembleBss(const elf::section &sec);

    int getSectionIndex(const elf::section &sec) const;
    const symbol_t * getSymbolAtOffset(std::vector<symbol_t> syms, int offset);
    static bool symbolCompareByOffset(symbol_t a, symbol_t b);
    static bool relocationCompareByOffset(relocation_t a, relocation_t b);
    std::map<int, std::deque<symbol_t>> symbolQueuesBySection(std::vector<symbol_t> symbols);
    std::map<int, std::vector<symbol_t>> groupSymbolsBySection(std::vector<symbol_t> symbols);
    void consumeUntilOffset(std::deque<symbol_t> &symbols, size_t offset);
    bool nextSym(std::deque<symbol_t> symbols, size_t offset, symbol_t *dest);
    bool nextRel(std::vector<relocation_t> &rels, size_t offset, relocation_t *dest);
    std::vector<symbol_t> filterDataSymbols(std::vector<symbol_t> &symbols);
    std::vector<symbol_t> filterArmSymbols(std::vector<symbol_t> &symbols);
    std::vector<symbol_t> filterModeSymbols(std::vector<symbol_t> &symbols);
    std::vector<symbol_t> filterElfSymbols(std::vector<symbol_t> &symbols);

    uint8_t consumeByte(const uint8_t **data);
    uint16_t consumeShort(const uint8_t **data);
    uint32_t consumeWord(const uint8_t **data);
    void printDataRelocation(const uint8_t **data, relocation_t rel);
    
    std::string get_symbol_type(uint8_t &sym_type);
    std::intptr_t get_rel_symbol_value(uint32_t &sym_idx, std::vector<symbol_t> &syms);
    std::string get_rel_symbol_name(uint32_t &sym_idx, std::vector<symbol_t> &syms);
    bool get_rel_symbol(uint32_t sym_idx, std::vector<symbol_t> &syms, symbol_t *dest);
    bool lookupSymbol(std::vector<symbol_t> &syms, size_t section_idx, size_t offset, symbol_t *dest);

    void initializeCapstone(csh *handle) const;
    std::vector<std::pair<size_t, ARMCodeSymbol>>
        getCodeSymbolsForSection(const elf::section &sec) const;

private:
    bool m_valid;
    const elf::elf* m_elf_file;
    std::vector<symbol_t> symbols;
    std::vector<symbol_t> data_symbols;
    std::vector<symbol_t> mode_symbols;
    std::vector<symbol_t> arm_symbols;
    std::vector<symbol_t> elf_symbols;
    std::map<int, std::deque<symbol_t>> symbolsBySection;
    std::map<int, std::deque<symbol_t>> dataSymbolsBySection;
    std::map<int, std::deque<symbol_t>> modeSymbolsBySection;
    std::map<int, std::deque<symbol_t>> armSymbolsBySection;
    std::map<int, std::vector<relocation_t>> relocationsBySection;

    struct CapstoneConfig final{
        public:
        CapstoneConfig():
        arch_type{CS_ARCH_ARM},
            mode{CS_MODE_THUMB},
            details{true}{
        }
        CapstoneConfig(const CapstoneConfig& src) = default;
        CapstoneConfig &operator=(const CapstoneConfig& src) = default;

        cs_arch arch_type;
        cs_mode mode;
        bool details;
    };
    CapstoneConfig m_config;
    int dataColumnWidth;
};
}



