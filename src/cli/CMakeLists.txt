add_executable(sec-cli sec_cli.cpp behavior_cmd.cpp behavior_bench.cpp)
target_include_directories(sec-cli PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(sec-cli PRIVATE sec_agent sec_behavior)
sec_apply_warnings(sec-cli)
