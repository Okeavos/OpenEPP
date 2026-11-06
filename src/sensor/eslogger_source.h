#pragma once

#include "sensor/sensor_service.h"

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace sec::sensor {

// Runs an event-producing command (normally `eslogger`), reads one JSON event per line from its
// stdout and feeds the parsed events to the SensorService. Restarts the command with backoff if it exits.
class EsloggerSource {
public:
    struct Status {
        std::string state = "stopped";  // stopped | starting | running | failed
        std::string last_error;
        std::uint64_t lines = 0;
        std::uint64_t parse_errors = 0;
        std::uint64_t restarts = 0;
    };

    EsloggerSource(std::vector<std::string> argv, SensorService& service);
    ~EsloggerSource();
    EsloggerSource(const EsloggerSource&) = delete;
    EsloggerSource& operator=(const EsloggerSource&) = delete;

    void start();
    void stop();
    Status status() const;

    // First restart delay and the cap, in milliseconds (tests use small values).
    void set_backoff(int initial_ms, int max_ms) {
        initial_backoff_ms_ = initial_ms;
        max_backoff_ms_ = max_ms;
    }

private:
    void run();
    bool wait_for_stop(int ms);
    void set_state(const std::string& state);
    void handle_line(const std::string& line);

    std::vector<std::string> argv_;
    SensorService& service_;
    std::thread thread_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    bool stop_ = false;
    Status status_;
    int initial_backoff_ms_ = 1000;
    int max_backoff_ms_ = 30000;
};

}
