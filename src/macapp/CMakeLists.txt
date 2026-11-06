add_executable(sec-menubar main.mm)
target_compile_options(sec-menubar PRIVATE -fobjc-arc -Wall -Wextra)
target_link_libraries(sec-menubar PRIVATE sec_agent sec_behavior sec_monitor "-framework Cocoa")
