#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sec {

struct PeSection {
    std::string name;
    std::uint32_t virtual_address = 0;
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_offset = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t characteristics = 0;
    double entropy = 0.0;

    bool executable() const { return (characteristics & 0x20000000u) != 0 || (characteristics & 0x20u) != 0; }
    bool writable() const { return (characteristics & 0x80000000u) != 0; }
};

struct PeInfo {
    bool is_64bit = false;
    bool is_dll = false;
    bool has_certificate = false;  // Authenticode directory present (NOT verified)
    std::uint16_t machine = 0;
    std::uint32_t timestamp = 0;
    std::uint32_t entry_point = 0;
    std::vector<PeSection> sections;
    std::vector<std::string> imported_dlls;
    std::vector<std::string> imported_functions;  // by name only, original case
};

double shannon_entropy(const std::uint8_t* data, std::size_t len);

// Bounds-checked static PE parser. Returns nullopt if the buffer is not a valid PE image.
std::optional<PeInfo> analyze_pe(const std::uint8_t* data, std::size_t size);

}
