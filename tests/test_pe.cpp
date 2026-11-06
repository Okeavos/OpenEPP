#include "test_framework.h"

#include "pe_builder.h"
#include "scanner/pe_analyzer.h"

#include <algorithm>

using namespace sec;
using namespace sec_test;

TEST(pe_rejects_garbage) {
    const std::vector<std::uint8_t> junk(300, 0x41);
    CHECK(!analyze_pe(junk.data(), junk.size()).has_value());
    CHECK(!analyze_pe(nullptr, 0).has_value());
    std::vector<std::uint8_t> mz(0x100, 0);
    mz[0] = 'M';
    mz[1] = 'Z';
    put32(mz, 0x3c, 0xfffffff0u);  // e_lfanew far outside the buffer
    CHECK(!analyze_pe(mz.data(), mz.size()).has_value());
}

TEST(pe_parses_headers_sections_and_imports) {
    SectionSpec text{".text", std::vector<std::uint8_t>(600, 0x90), 0x60000020};
    auto img = make_pe({text}, {"CreateFileW", "VirtualAllocEx", "WriteProcessMemory"}, true);
    const auto pe = analyze_pe(img.data(), img.size());
    CHECK(pe.has_value());
    if (!pe) return;
    CHECK(pe->is_64bit);
    CHECK(!pe->is_dll);
    CHECK(pe->has_certificate);
    CHECK(pe->sections.size() == 2);
    CHECK(pe->sections[0].name == ".text");
    CHECK(pe->sections[0].executable());
    CHECK(!pe->sections[0].writable());
    CHECK(pe->imported_dlls.size() == 1);
    CHECK(pe->imported_dlls[0] == "KERNEL32.dll");
    CHECK(pe->imported_functions.size() == 3);
    CHECK(std::find(pe->imported_functions.begin(), pe->imported_functions.end(), "VirtualAllocEx") !=
          pe->imported_functions.end());
}

TEST(pe_survives_truncation_at_every_length) {
    SectionSpec text{".text", random_bytes(2000), 0x60000020};
    const auto img = make_pe({text}, {"CreateFileW", "ExitProcess"});
    // Must never crash or read out of bounds, whatever prefix of the file we get.
    for (std::size_t len = 0; len <= img.size(); len += 7) {
        (void)analyze_pe(img.data(), len);
    }
    CHECK(true);
}

TEST(entropy_values) {
    const std::vector<std::uint8_t> zeros(4096, 0);
    CHECK(shannon_entropy(zeros.data(), zeros.size()) == 0.0);
    const auto rnd = random_bytes(65536);
    CHECK(shannon_entropy(rnd.data(), rnd.size()) > 7.9);
    std::vector<std::uint8_t> two(4096);
    for (std::size_t i = 0; i < two.size(); ++i) two[i] = (i % 2) ? 0xff : 0x00;
    const double e = shannon_entropy(two.data(), two.size());
    CHECK(e > 0.99 && e < 1.01);
}
