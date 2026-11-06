#pragma once

// Tiny dependency-free test harness.

#include <cstdio>
#include <filesystem>
#include <functional>
#include <random>
#include <string>
#include <vector>

namespace sec_test {

struct TestCase {
    const char* name;
    std::function<void()> fn;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}

inline int& failures() {
    static int f = 0;
    return f;
}

inline int& checks() {
    static int c = 0;
    return c;
}

struct Registrar {
    Registrar(const char* name, std::function<void()> fn) { registry().push_back({name, std::move(fn)}); }
};

// Temporary directory removed on destruction.
class TempDir {
public:
    TempDir() {
        std::random_device rd;
        path_ = std::filesystem::temp_directory_path() / ("sec_test_" + std::to_string(rd()));
        std::filesystem::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;
    const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
};

}

#define TEST(name)                                                              \
    static void test_##name();                                                  \
    static ::sec_test::Registrar registrar_##name(#name, &test_##name);         \
    static void test_##name()

#define CHECK(cond)                                                                       \
    do {                                                                                  \
        ++::sec_test::checks();                                                           \
        if (!(cond)) {                                                                    \
            ++::sec_test::failures();                                                     \
            std::fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);        \
        }                                                                                 \
    } while (0)
