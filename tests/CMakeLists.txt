add_executable(sec_tests
    test_main.cpp
    test_common.cpp
    test_pe.cpp
    test_scan.cpp
    test_realtime.cpp
    test_json.cpp
    test_behavior.cpp
)
target_link_libraries(sec_tests PRIVATE sec_agent sec_behavior)
target_include_directories(sec_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
sec_apply_warnings(sec_tests)
add_test(NAME sec_tests COMMAND sec_tests)
