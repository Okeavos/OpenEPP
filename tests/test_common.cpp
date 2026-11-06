#include "test_framework.h"

#include "common/config.h"
#include "common/sha256.h"
#include "common/util.h"
#include "scanner/hash_db.h"

#include <fstream>

using namespace sec;

namespace {
std::string sha_of(const std::string& s) { return Sha256::to_hex(Sha256::of(s.data(), s.size())); }
}

TEST(sha256_known_vectors) {
    CHECK(sha_of("") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(sha_of("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(sha_of("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq") ==
          "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(sha256_streaming_matches_oneshot) {
    const std::string big(1000003, 'x');
    Sha256 h;
    std::size_t pos = 0;
    std::size_t step = 1;
    while (pos < big.size()) {
        const std::size_t n = std::min(step, big.size() - pos);
        h.update(big.data() + pos, n);
        pos += n;
        step = step * 3 + 1;
    }
    CHECK(Sha256::to_hex(h.finish()) == sha_of(big));
    // million 'a' known vector
    const std::string million(1000000, 'a');
    CHECK(sha_of(million) == "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

TEST(util_helpers) {
    CHECK(util::to_lower("AbC") == "abc");
    CHECK(util::trim("  x \t") == "x");
    const auto parts = util::split("a;b;;c", ';');
    CHECK(parts.size() == 4);
    CHECK(parts[2].empty());
    CHECK(util::is_hex("deadBEEF09"));
    CHECK(!util::is_hex("xyz"));
}

TEST(sha256_file_matches_memory) {
    sec_test::TempDir tmp;
    const auto p = tmp.path() / "f.bin";
    {
        std::ofstream f(p, std::ios::binary);
        f << "hello world";
    }
    const auto h = util::sha256_file(p);
    CHECK(h.has_value());
    CHECK(*h == sha_of("hello world"));
    CHECK(!util::sha256_file(tmp.path() / "missing").has_value());
}

TEST(config_parsing) {
    sec_test::TempDir tmp;
    const auto p = tmp.path() / "c.conf";
    {
        std::ofstream f(p);
        f << "# comment\n"
             "Auto_Quarantine = true\n"
             "scan_interval_minutes=15\n"
             "; another comment\n"
             "bad_int = 12x\n"
             "scan_paths = C:\\a;D:\\b\n";
    }
    Config c;
    CHECK(c.load(p));
    CHECK(c.get_bool("auto_quarantine", false));
    CHECK(c.get_int("scan_interval_minutes", 0) == 15);
    CHECK(c.get_int("bad_int", 7) == 7);
    CHECK(c.get("scan_paths") == "C:\\a;D:\\b");
    CHECK(!c.has("nope"));
    CHECK(!c.load(tmp.path() / "missing.conf"));
}

TEST(hash_db_load_and_lookup) {
    sec_test::TempDir tmp;
    const auto p = tmp.path() / "hashes.txt";
    const std::string good(64, 'a');
    {
        std::ofstream f(p);
        f << "# header\n"
          << good << " Trojan.Test\n"
          << "tooshort Bad\n"
          << std::string(64, 'B') << "\n";
    }
    HashDb db;
    CHECK(db.load_file(p) == 2);
    CHECK(db.find(good) != nullptr);
    CHECK(*db.find(good) == "Trojan.Test");
    CHECK(db.find(std::string(64, 'b')) != nullptr);  // case-insensitive
    CHECK(db.find(std::string(64, 'c')) == nullptr);
    CHECK(!db.add("zz", "x"));
}
