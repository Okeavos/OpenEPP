#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace sec::behavior::net {

bool parse_ipv4(std::string_view s, std::uint32_t& out);

// True for loopback, RFC1918, link-local, CGNAT, multicast/reserved and unparsable input
// (i.e. anything we do not treat as "a public internet destination").
bool is_private_or_local(std::string_view ip);

// spec: "a.b.c.d/n" CIDR (IPv4) or an exact address string.
bool ip_matches(std::string_view ip, std::string_view spec);

// pattern: exact host, or "*.example.com" (matches example.com and any subdomain). Case-insensitive.
bool host_matches(std::string_view host, std::string_view pattern);

double shannon_entropy(std::string_view s);

// "a.b.example.co.kr" -> "example.co.kr"
std::string registrable_domain(std::string_view name);

// Heuristic: algorithmically generated second-level label (long, high entropy, few vowels or many digits).
bool looks_like_dga(std::string_view name);

// Heuristic: query name shaped like DNS tunnelling (very long name or label, encoded-looking subdomain).
bool looks_like_tunnel(std::string_view name);

}
