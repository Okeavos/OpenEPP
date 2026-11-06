add_library(sec_monitor STATIC fs_monitor_mac.cpp)
target_include_directories(sec_monitor PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(sec_monitor PUBLIC "-framework CoreServices")
sec_apply_warnings(sec_monitor)
