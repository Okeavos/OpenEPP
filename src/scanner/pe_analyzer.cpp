#include "scanner/pe_analyzer.h"

#include <algorithm>
#include <cmath>

namespace sec {

namespace {

class Reader {
public:
    Reader(const std::uint8_t* d, std::uint64_t n) : d_(d), n_(n) {}

    bool u16(std::uint64_t off, std::uint16_t& v) const {
        if (off > n_ || n_ - off < 2) return false;
        v = static_cast<std::uint16_t>(d_[off] | (d_[off + 1] << 8));
        return true;
    }

    bool u32(std::uint64_t off, std::uint32_t& v) const {
        if (off > n_ || n_ - off < 4) return false;
        v = static_cast<std::uint32_t>(d_[off]) | (static_cast<std::uint32_t>(d_[off + 1]) << 8) |
            (static_cast<std::uint32_t>(d_[off + 2]) << 16) | (static_cast<std::uint32_t>(d_[off + 3]) << 24);
        return true;
    }

    bool u64(std::uint64_t off, std::uint64_t& v) const {
        std::uint32_t lo = 0;
        std::uint32_t hi = 0;
        if (!u32(off, lo) || !u32(off + 4, hi)) return false;
        v = (static_cast<std::uint64_t>(hi) << 32) | lo;
        return true;
    }

    // Reads a NUL-terminated string of at most max_len chars; fails if it is not terminated in range.
    bool cstr(std::uint64_t off, std::size_t max_len, std::string& out) const {
        out.clear();
        for (std::size_t i = 0; i < max_len; ++i) {
            if (off + i >= n_) return false;
            const char c = static_cast<char>(d_[off + i]);
            if (c == '\0') return true;
            out.push_back(c);
        }
        return false;
    }

    std::uint64_t size() const { return n_; }

private:
    const std::uint8_t* d_;
    std::uint64_t n_;
};

std::optional<std::uint64_t> rva_to_offset(const std::vector<PeSection>& sections, std::uint64_t rva,
                                           std::uint64_t file_size) {
    for (const PeSection& s : sections) {
        const std::uint64_t span = std::max<std::uint64_t>(s.virtual_size, s.raw_size);
        if (rva >= s.virtual_address && rva < static_cast<std::uint64_t>(s.virtual_address) + span) {
            const std::uint64_t off = rva - s.virtual_address + s.raw_offset;
            if (off < file_size) return off;
            return std::nullopt;
        }
    }
    return std::nullopt;
}

void parse_imports(const Reader& rd, PeInfo& info, std::uint32_t import_rva) {
    const auto base = rva_to_offset(info.sections, import_rva, rd.size());
    if (!base) return;

    constexpr std::size_t kMaxDlls = 512;
    constexpr std::size_t kMaxFunctions = 20000;

    for (std::size_t i = 0; i < kMaxDlls; ++i) {
        const std::uint64_t desc = *base + i * 20;
        std::uint32_t oft = 0;
        std::uint32_t name_rva = 0;
        std::uint32_t ft = 0;
        if (!rd.u32(desc, oft) || !rd.u32(desc + 12, name_rva) || !rd.u32(desc + 16, ft)) return;
        if (oft == 0 && name_rva == 0 && ft == 0) return;

        if (const auto name_off = rva_to_offset(info.sections, name_rva, rd.size())) {
            std::string dll;
            if (rd.cstr(*name_off, 260, dll) && !dll.empty()) info.imported_dlls.push_back(dll);
        }

        const std::uint32_t thunk_rva = oft != 0 ? oft : ft;
        const auto thunk_off = rva_to_offset(info.sections, thunk_rva, rd.size());
        if (!thunk_off) continue;

        const std::size_t entry_size = info.is_64bit ? 8 : 4;
        for (std::size_t j = 0; j < 4096 && info.imported_functions.size() < kMaxFunctions; ++j) {
            std::uint64_t entry = 0;
            const std::uint64_t at = *thunk_off + j * entry_size;
            if (info.is_64bit) {
                if (!rd.u64(at, entry)) break;
            } else {
                std::uint32_t e32 = 0;
                if (!rd.u32(at, e32)) break;
                entry = e32;
            }
            if (entry == 0) break;
            const std::uint64_t ordinal_flag = info.is_64bit ? (1ull << 63) : (1ull << 31);
            if (entry & ordinal_flag) continue;  // imported by ordinal
            const auto hint_off = rva_to_offset(info.sections, entry & 0x7fffffffull, rd.size());
            if (!hint_off) continue;
            std::string fn;
            if (rd.cstr(*hint_off + 2, 256, fn) && !fn.empty()) info.imported_functions.push_back(std::move(fn));
        }
    }
}

}

double shannon_entropy(const std::uint8_t* data, std::size_t len) {
    if (len == 0) return 0.0;
    std::uint64_t counts[256] = {};
    for (std::size_t i = 0; i < len; ++i) ++counts[data[i]];
    double h = 0.0;
    for (const std::uint64_t c : counts) {
        if (c == 0) continue;
        const double p = static_cast<double>(c) / static_cast<double>(len);
        h -= p * std::log2(p);
    }
    return h;
}

std::optional<PeInfo> analyze_pe(const std::uint8_t* data, std::size_t size) {
    if (data == nullptr || size < 0x40 || data[0] != 'M' || data[1] != 'Z') return std::nullopt;
    const Reader rd(data, size);

    std::uint32_t pe_off = 0;
    std::uint32_t sig = 0;
    if (!rd.u32(0x3c, pe_off) || !rd.u32(pe_off, sig) || sig != 0x00004550u) return std::nullopt;

    const std::uint64_t coff = static_cast<std::uint64_t>(pe_off) + 4;
    std::uint16_t machine = 0;
    std::uint16_t nsec = 0;
    std::uint16_t opt_size = 0;
    std::uint16_t chars = 0;
    std::uint32_t ts = 0;
    if (!rd.u16(coff, machine) || !rd.u16(coff + 2, nsec) || !rd.u32(coff + 4, ts) ||
        !rd.u16(coff + 16, opt_size) || !rd.u16(coff + 18, chars)) {
        return std::nullopt;
    }
    if (nsec == 0 || nsec > 96) return std::nullopt;

    const std::uint64_t opt = coff + 20;
    std::uint16_t magic = 0;
    if (!rd.u16(opt, magic)) return std::nullopt;

    PeInfo info;
    if (magic == 0x10b) {
        info.is_64bit = false;
    } else if (magic == 0x20b) {
        info.is_64bit = true;
    } else {
        return std::nullopt;
    }
    info.machine = machine;
    info.timestamp = ts;
    info.is_dll = (chars & 0x2000u) != 0;
    if (!rd.u32(opt + 16, info.entry_point)) return std::nullopt;

    std::uint32_t num_dirs = 0;
    const std::uint64_t dirs_off = opt + (info.is_64bit ? 112 : 96);
    if (!rd.u32(opt + (info.is_64bit ? 108 : 92), num_dirs)) return std::nullopt;

    auto dir = [&](std::uint32_t index, std::uint32_t& rva, std::uint32_t& dsize) {
        rva = 0;
        dsize = 0;
        if (index >= num_dirs || index >= 16) return false;
        return rd.u32(dirs_off + index * 8ull, rva) && rd.u32(dirs_off + index * 8ull + 4, dsize);
    };

    const std::uint64_t table = opt + opt_size;
    for (std::uint16_t i = 0; i < nsec; ++i) {
        const std::uint64_t off = table + static_cast<std::uint64_t>(i) * 40;
        if (off + 40 > size) break;
        PeSection s;
        for (int k = 0; k < 8 && data[off + k] != 0; ++k) s.name.push_back(static_cast<char>(data[off + k]));
        rd.u32(off + 8, s.virtual_size);
        rd.u32(off + 12, s.virtual_address);
        rd.u32(off + 16, s.raw_size);
        rd.u32(off + 20, s.raw_offset);
        rd.u32(off + 36, s.characteristics);
        if (s.raw_offset < size && s.raw_size > 0) {
            const std::size_t len = static_cast<std::size_t>(std::min<std::uint64_t>(s.raw_size, size - s.raw_offset));
            s.entropy = shannon_entropy(data + s.raw_offset, len);
        }
        info.sections.push_back(std::move(s));
    }
    if (info.sections.empty()) return std::nullopt;

    std::uint32_t rva = 0;
    std::uint32_t dsize = 0;
    if (dir(4, rva, dsize)) info.has_certificate = dsize != 0;
    if (dir(1, rva, dsize) && rva != 0) parse_imports(rd, info, rva);

    return info;
}

}
