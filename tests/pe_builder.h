#pragma once

// Builds small synthetic PE32+ images for tests (not runnable, only parseable).

#include <cstdint>
#include <cstring>
#include <random>
#include <string>
#include <vector>

namespace sec_test {

struct SectionSpec {
    std::string name;
    std::vector<std::uint8_t> data;
    std::uint32_t characteristics = 0x60000020;  // code, exec, read
};

inline void put16(std::vector<std::uint8_t>& v, std::size_t off, std::uint16_t x) {
    v[off] = static_cast<std::uint8_t>(x & 0xff);
    v[off + 1] = static_cast<std::uint8_t>(x >> 8);
}

inline void put32(std::vector<std::uint8_t>& v, std::size_t off, std::uint32_t x) {
    for (int i = 0; i < 4; ++i) v[off + i] = static_cast<std::uint8_t>((x >> (8 * i)) & 0xff);
}

inline void put64(std::vector<std::uint8_t>& v, std::size_t off, std::uint64_t x) {
    for (int i = 0; i < 8; ++i) v[off + i] = static_cast<std::uint8_t>((x >> (8 * i)) & 0xff);
}

inline std::vector<std::uint8_t> random_bytes(std::size_t n, unsigned seed = 1234) {
    std::mt19937 gen(seed);
    std::vector<std::uint8_t> v(n);
    for (auto& b : v) b = static_cast<std::uint8_t>(gen() & 0xff);
    return v;
}

// Layout: [0x00] dll name "KERNEL32.dll" at +0x30, descriptor at +0, thunks at +0x40, hint/names after.
inline std::vector<std::uint8_t> make_idata(std::uint32_t va, const std::vector<std::string>& imports) {
    const std::size_t thunks = 0x40;
    std::vector<std::uint8_t> d(thunks + 8 * (imports.size() + 1), 0);
    const char dll[] = "KERNEL32.dll";
    std::memcpy(&d[0x30], dll, sizeof(dll));
    for (std::size_t i = 0; i < imports.size(); ++i) {
        const std::uint32_t rva = va + static_cast<std::uint32_t>(d.size());
        d.push_back(0);  // hint (2 bytes)
        d.push_back(0);
        d.insert(d.end(), imports[i].begin(), imports[i].end());
        d.push_back(0);
        if (d.size() % 2) d.push_back(0);
        put64(d, thunks + 8 * i, rva);
    }
    put32(d, 0, va + static_cast<std::uint32_t>(thunks));    // OriginalFirstThunk
    put32(d, 12, va + 0x30);                                  // Name
    put32(d, 16, va + static_cast<std::uint32_t>(thunks));    // FirstThunk
    return d;
}

inline std::vector<std::uint8_t> make_pe(std::vector<SectionSpec> sections, const std::vector<std::string>& imports,
                                         bool signed_dir = false) {
    const std::uint32_t kAlign = 0x1000;
    const std::size_t kHeaders = 0x200;
    const bool with_imports = !imports.empty();
    if (with_imports) {
        const std::uint32_t idata_va = kAlign * static_cast<std::uint32_t>(sections.size() + 1);
        sections.push_back({".idata", make_idata(idata_va, imports), 0x40000040});
    }
    const std::size_t n = sections.size();

    std::vector<std::size_t> raw_sizes;
    std::size_t total = kHeaders;
    for (const auto& s : sections) {
        const std::size_t rs = (s.data.size() + 0x1ff) & ~static_cast<std::size_t>(0x1ff);
        raw_sizes.push_back(rs);
        total += rs;
    }

    std::vector<std::uint8_t> f(total, 0);
    f[0] = 'M';
    f[1] = 'Z';
    put32(f, 0x3c, 0x40);
    f[0x40] = 'P';
    f[0x41] = 'E';
    put16(f, 0x44, 0x8664);                                 // machine
    put16(f, 0x46, static_cast<std::uint16_t>(n));          // number of sections
    put32(f, 0x48, 0x5f000000);                             // timestamp
    put16(f, 0x54, 240);                                    // size of optional header
    put16(f, 0x56, 0x0022);                                 // characteristics: executable, large address aware

    const std::size_t opt = 0x58;
    put16(f, opt, 0x20b);                                   // PE32+
    put32(f, opt + 16, kAlign);                             // entry point
    put32(f, opt + 108, 16);                                // number of data directories
    if (with_imports) {
        put32(f, opt + 112 + 8, kAlign * static_cast<std::uint32_t>(n));  // import dir RVA (.idata is last)
        put32(f, opt + 112 + 8 + 4, 40);
    }
    if (signed_dir) {
        put32(f, opt + 112 + 4 * 8, 0x1000);
        put32(f, opt + 112 + 4 * 8 + 4, 0x200);
    }

    std::size_t table = opt + 240;
    std::size_t raw = kHeaders;
    for (std::size_t i = 0; i < n; ++i) {
        const auto& s = sections[i];
        const std::size_t e = table + i * 40;
        std::memcpy(&f[e], s.name.data(), std::min<std::size_t>(s.name.size(), 8));
        put32(f, e + 8, static_cast<std::uint32_t>(s.data.size()));
        put32(f, e + 12, kAlign * static_cast<std::uint32_t>(i + 1));
        put32(f, e + 16, static_cast<std::uint32_t>(raw_sizes[i]));
        put32(f, e + 20, static_cast<std::uint32_t>(raw));
        put32(f, e + 36, s.characteristics);
        std::memcpy(&f[raw], s.data.data(), s.data.size());
        raw += raw_sizes[i];
    }
    return f;
}

}
