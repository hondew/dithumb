#pragma once

#include <map>
#include <vector>

namespace disasm
{
    enum class LabelType : std::int16_t {
        kData,
        kInsn
    };

    typedef struct {
        int section_idx;
        // Offset within the section
        int offset;
    } Address;

    typedef struct {
        LabelType type;
        std::string name;
        Address address;
    } Label;

/**
 * LabelProcessor
 */
    class LabelProcessor
    {
    public:
        LabelProcessor();
        ~LabelProcessor() = default;

        void addLabel(Address address, LabelType type);
        void generateLabels(void);
        std::vector<Label> getLabelsInSection(int section_idx);
        bool lookupLabel(Address address, Label *dest);

    private:
        static bool labelCompare(Label a, Label b);

    private:
        std::map<int, std::vector<Label>> labelsBySection;
    };
} // namespace disasm
