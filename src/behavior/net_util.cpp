#include "behavior/net_util.h"

#include "common/util.h"

#include <algorithm>
#include <cmath>
#include <vector>

namespace sec::behavior::net {

bool parse_ipv4(std::string_view s, std::uint32_t& out) {
    std::uint32_t result = 0;
    int parts = 0;
    std::size_t i = 0;
    while (i <= s.size()) {
        std::size_t j = i;
        std::uint32_t octet = 0;
        int digits = 0;
        while (j < s.size() && s[j] >= '0' && s[j] <= '9') {
            octet = octet * 10 + static_cast<std::uint32_t>(s[j] - '0');
            if (++digits > 3 || octet > 255) return false;
            ++j;
        }
        if (digits == 0) return false;
        result = (result << 8) | octet;
        ++parts;
        if (j == s.size()) break;
        if (s[j] != '.') return false;
        i = j + 1;
    }
    if (parts != 4) return false;
    out = result;
    return true;
}

bool is_private_or_local(std::string_view ip) {
    std::uint32_t v = 0;
    if (parse_ipv4(ip, v)) {
        const std::uint32_t a = v >> 24;
        const std::uint32_t b = (v >> 16) & 0xff;
        if (a == 0 || a == 10 || a == 127) return true;
        if (a == 169 && b == 254) return true;
        if (a == 172 && b >= 16 && b <= 31) return true;
        if (a == 192 && b == 168) return true;
        if (a == 100 && b >= 64 && b <= 127) return true;
        if (a >= 224) return true;
        return false;
    }
    if (ip.find(':') == std::string_view::npos) return true;

    const std::string l = util::to_lower(std::string(ip));
    if (l == "::1" || l == "::") return true;
    if (l.rfind("::ffff:", 0) == 0) return is_private_or_local(std::string_view(l).substr(7));
    if (l.size() >= 2) {
        if (l.rfind("fe8", 0) == 0 || l.rfind("fe9", 0) == 0 || l.rfind("fea", 0) == 0 || l.rfind("feb", 0) == 0) return true;
        if (l.rfind("fc", 0) == 0 || l.rfind("fd", 0) == 0 || l.rfind("ff", 0) == 0) return true;
    }
    return false;
}

bool ip_matches(std::string_view ip, std::string_view spec) {
    const std::size_t slash = spec.find('/');
    if (slash == std::string_view::npos) {
        return util::to_lower(std::string(ip)) == util::to_lower(std::string(spec));
    }
    std::uint32_t base = 0;
    std::uint32_t addr = 0;
    if (!parse_ipv4(spec.substr(0, slash), base) || !parse_ipv4(ip, addr)) return false;
    int prefix = 0;
    for (const char c : spec.substr(slash + 1)) {
        if (c < '0' || c > '9') return false;
        prefix = prefix * 10 + (c - '0');
        if (prefix > 32) return false;
    }
    if (prefix == 0) return true;
    const std::uint32_t mask = prefix == 32 ? 0xffffffffu : ~((1u << (32 - prefix)) - 1u);
    return (base & mask) == (addr & mask);
}

bool host_matches(std::string_view host, std::string_view pattern) {
    const std::string h = util::to_lower(std::string(host));
    const std::string p = util::to_lower(std::string(pattern));
    if (p.size() > 2 && p[0] == '*' && p[1] == '.') {
        const std::string suffix = p.substr(2);
        if (h == suffix) return true;
        return h.size() > suffix.size() && h.compare(h.size() - suffix.size(), suffix.size(), suffix) == 0 &&
               h[h.size() - suffix.size() - 1] == '.';
    }
    return h == p;
}

double shannon_entropy(std::string_view s) {
    if (s.empty()) return 0.0;
    std::size_t counts[256] = {};
    for (const char c : s) ++counts[static_cast<unsigned char>(c)];
    double h = 0.0;
    for (const std::size_t c : counts) {
        if (c == 0) continue;
        const double p = static_cast<double>(c) / static_cast<double>(s.size());
        h -= p * std::log2(p);
    }
    return h;
}

namespace {

std::string normalize(std::string_view name) {
    std::string n = util::to_lower(std::string(name));
    while (!n.empty() && n.back() == '.') n.pop_back();
    return n;
}

}

std::string registrable_domain(std::string_view name) {
    static const char* const kTwoLevel[] = {"co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr", "re.kr", "pe.kr", "co.uk",
                                            "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.jp", "or.jp",
                                            "ne.jp", "com.cn", "com.br", "co.in", "co.nz", "com.tw", "com.hk",
                                            "com.sg"};
    const std::string n = normalize(name);
    const std::vector<std::string> labels = util::split(n, '.');
    if (labels.size() <= 2) return n;
    const std::string last2 = labels[labels.size() - 2] + "." + labels.back();
    std::size_t take = 2;
    for (const char* t : kTwoLevel) {
        if (last2 == t) {
            take = 3;
            break;
        }
    }
    if (labels.size() < take) return n;
    std::string out;
    for (std::size_t i = labels.size() - take; i < labels.size(); ++i) {
        if (!out.empty()) out.push_back('.');
        out += labels[i];
    }
    return out;
}

bool looks_like_dga(std::string_view name) {
    const std::string reg = registrable_domain(name);
    const std::size_t dot = reg.find('.');
    const std::string label = dot == std::string::npos ? reg : reg.substr(0, dot);
    if (label.size() < 12 || label.rfind("xn--", 0) == 0) return false;

    std::size_t vowels = 0;
    std::size_t digits = 0;
    for (const char c : label) {
        if (c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u') ++vowels;
        if (c >= '0' && c <= '9') ++digits;
    }
    const double n = static_cast<double>(label.size());
    const double vowel_ratio = static_cast<double>(vowels) / n;
    const double digit_ratio = static_cast<double>(digits) / n;
    return shannon_entropy(label) >= 3.3 && (vowel_ratio <= 0.25 || digit_ratio >= 0.25);
}

bool looks_like_tunnel(std::string_view name) {
    const std::string n = normalize(name);
    if (n.size() > 100) return true;
    const std::vector<std::string> labels = util::split(n, '.');
    std::size_t longest = 0;
    for (const std::string& l : labels) longest = std::max(longest, l.size());
    if (longest > 45) return true;

    const std::string reg = registrable_domain(n);
    if (n.size() > reg.size() + 1) {
        const std::string sub = n.substr(0, n.size() - reg.size() - 1);
        if (labels.size() >= 5 && sub.size() > 50 && shannon_entropy(sub) >= 3.5) return true;
    }
    return false;
}

}
