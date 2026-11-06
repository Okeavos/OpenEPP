add_executable(sec-service service_main.cpp)
target_link_libraries(sec-service PRIVATE sec_agent advapi32)
sec_apply_warnings(sec-service)
