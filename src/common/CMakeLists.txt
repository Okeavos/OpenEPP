add_library(sec_common STATIC
    sha256.cpp
    util.cpp
    log.cpp
    config.cpp
    json.cpp
)
target_include_directories(sec_common PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_compile_features(sec_common PUBLIC cxx_std_20)
sec_apply_warnings(sec_common)
