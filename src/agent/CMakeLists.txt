add_library(sec_agent STATIC
    agent.cpp
    detection_store.cpp
    realtime.cpp
)
target_include_directories(sec_agent PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
target_link_libraries(sec_agent PUBLIC sec_scanner)
find_package(Threads REQUIRED)
target_link_libraries(sec_agent PUBLIC Threads::Threads)
sec_apply_warnings(sec_agent)
