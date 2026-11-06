add_executable(sec-agentd agentd.cpp)
target_link_libraries(sec-agentd PRIVATE sec_agent)
sec_apply_warnings(sec-agentd)
