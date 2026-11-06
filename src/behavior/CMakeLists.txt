add_library(sec_behavior STATIC
    event.cpp
    process_tree.cpp
    net_util.cpp
    rules.cpp
    default_rules.cpp
    engine.cpp
    es_parser.cpp
    alert_store.cpp
)
target_link_libraries(sec_behavior PUBLIC sec_common)
target_include_directories(sec_behavior PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
sec_apply_warnings(sec_behavior)
