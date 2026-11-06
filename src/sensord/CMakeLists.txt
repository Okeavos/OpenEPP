add_executable(sec-sensord sensord.cpp)
target_link_libraries(sec-sensord PRIVATE sec_sensor sec_agent)
sec_apply_warnings(sec-sensord)
