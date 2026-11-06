add_library(sec_scanner STATIC
    hash_db.cpp
    pe_analyzer.cpp
    quarantine.cpp
    scan_engine.cpp
)
target_include_directories(sec_scanner PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(sec_scanner PUBLIC sec_common)
sec_apply_warnings(sec_scanner)
