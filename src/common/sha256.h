#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

namespace sec {

class Sha256 {
public:
    using Digest = std::array<std::uint8_t, 32>;

    Sha256();

    void update(const void* data, std::size_t len);
    Digest finish();

    static Digest of(const void* data, std::size_t len);
    static std::string to_hex(const Digest& digest);

private:
    void transform(const std::uint8_t* block);

    std::uint32_t state_[8];
    std::uint64_t bit_length_;
    std::uint8_t buffer_[64];
    std::size_t buffer_length_;
};

}
