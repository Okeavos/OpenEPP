find_package(Threads REQUIRED)
set(SEC_SENSOR_SOURCES
    sensor_service.cpp
    conn_tracker.cpp
    socket_poller.cpp
    eslogger_source.cpp
    alert_enricher.cpp
)
if(APPLE)
    list(APPEND SEC_SENSOR_SOURCES socket_snapshot_mac.cpp proc_snapshot_mac.cpp)
else()
    list(APPEND SEC_SENSOR_SOURCES proc_snapshot_proc.cpp)
endif()

add_library(sec_sensor STATIC ${SEC_SENSOR_SOURCES})
target_link_libraries(sec_sensor PUBLIC sec_behavior sec_scanner Threads::Threads)
if(APPLE)
    target_link_libraries(sec_sensor PUBLIC "-framework Security" "-framework CoreFoundation")
endif()
target_include_directories(sec_sensor PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/..)
sec_apply_warnings(sec_sensor)
