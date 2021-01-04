#include "LabelProcessor.h"
#include <algorithm>

namespace disasm
{
LabelProcessor::LabelProcessor() {}

void
LabelProcessor::addLabel(Address address, LabelType type) {
    Label l = {type : type, address : address};
    labelsBySection[address.section_idx].push_back(l);
}

bool
LabelProcessor::labelCompare(Label a, Label b) {
    return a.address.offset < b.address.offset; 
}

/**
 * Generate unique names for each label. Must be called before lookupLabel().
 */
void
LabelProcessor::generateLabels(void) {
    // Simplest method: Label names are monotically rising numbers sorted
    // increasingly by section and offset within section.
        
    // Sort each vector of labels by offset
    for (auto &[section_id, labels] : labelsBySection) {
        std::sort(labels.begin(), labels.end(), labelCompare);
    }
    
    int counter = 1;
    char name[100];
    for (auto &[section_id, labels] : labelsBySection) {
        for (auto &label : labels) {
            sprintf(name, ".L%d", counter);
            label.name = std::string(name);
            counter++;
        }
    }
}

/**
 * Return all labels in a section sorted by offset within section.
 */
std::vector<Label>
LabelProcessor::getLabelsInSection(int section_idx) {
    return labelsBySection[section_idx];
}

bool
LabelProcessor::lookupLabel(Address address, Label *dest) {
    auto labels = labelsBySection[address.section_idx];
    for (auto label : labels) {
        if (label.address.offset == address.offset) {
            *dest = label;
            return true;
        }
    }
    return false;
}

} // namespace disasm
