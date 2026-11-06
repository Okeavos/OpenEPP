#include "sensor/eslogger_source.h"

#include "behavior/es_parser.h"
#include "common/log.h"

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__APPLE__)
#include <crt_externs.h>
#else
extern char** environ;
#endif

namespace sec::sensor {

namespace {

constexpr std::size_t kMaxLine = 8u * 1024u * 1024u;

char** process_environ() {
#if defined(__APPLE__)
    return *_NSGetEnviron();
#else
    return environ;
#endif
}

void set_cloexec(int fd) {
    const int flags = fcntl(fd, F_GETFD);
    if (flags >= 0) fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

std::string last_line(const std::string& text) {
    std::size_t end = text.size();
    while (end > 0 && (text[end - 1] == '\n' || text[end - 1] == '\r' || text[end - 1] == ' ')) --end;
    if (end == 0) return std::string();
    const std::size_t nl = text.rfind('\n', end - 1);
    std::string line = text.substr(nl == std::string::npos ? 0 : nl + 1, end - (nl == std::string::npos ? 0 : nl + 1));
    if (line.size() > 300) line.resize(300);
    return line;
}

}

EsloggerSource::EsloggerSource(std::vector<std::string> argv, SensorService& service)
    : argv_(std::move(argv)), service_(service) {}

EsloggerSource::~EsloggerSource() { stop(); }

void EsloggerSource::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (thread_.joinable() || argv_.empty()) return;
    stop_ = false;
    status_.state = "starting";
    thread_ = std::thread([this] { run(); });
}

void EsloggerSource::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stop_ = true;
    }
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
    std::lock_guard<std::mutex> lock(mutex_);
    status_.state = "stopped";
}

EsloggerSource::Status EsloggerSource::status() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return status_;
}

void EsloggerSource::set_state(const std::string& state) {
    std::lock_guard<std::mutex> lock(mutex_);
    status_.state = state;
}

bool EsloggerSource::wait_for_stop(int ms) {
    std::unique_lock<std::mutex> lock(mutex_);
    return cv_.wait_for(lock, std::chrono::milliseconds(ms), [this] { return stop_; });
}

void EsloggerSource::handle_line(const std::string& line) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ++status_.lines;
    }
    behavior::ParseResult r = behavior::parse_event_line(line);
    if (r.status == behavior::ParseResult::Status::Skipped) return;
    if (r.status == behavior::ParseResult::Status::Error) {
        std::lock_guard<std::mutex> lock(mutex_);
        ++status_.parse_errors;
        if (status_.parse_errors <= 5) log::warn("event parse error: " + r.error);
        return;
    }
    service_.submit(std::move(r.event));
}

void EsloggerSource::run() {
    int backoff = initial_backoff_ms_;
    bool first = true;

    while (true) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (stop_) return;
            if (!first) ++status_.restarts;
            status_.state = "starting";
        }
        first = false;

        int out_pipe[2] = {-1, -1};
        int err_pipe[2] = {-1, -1};
        if (pipe(out_pipe) != 0 || pipe(err_pipe) != 0) {
            std::lock_guard<std::mutex> lock(mutex_);
            status_.state = "failed";
            status_.last_error = std::string("pipe failed: ") + std::strerror(errno);
            if (out_pipe[0] >= 0) {
                close(out_pipe[0]);
                close(out_pipe[1]);
            }
            return;
        }
        for (const int fd : {out_pipe[0], out_pipe[1], err_pipe[0], err_pipe[1]}) set_cloexec(fd);

        posix_spawn_file_actions_t actions;
        posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0);
        posix_spawn_file_actions_adddup2(&actions, out_pipe[1], 1);
        posix_spawn_file_actions_adddup2(&actions, err_pipe[1], 2);

        std::vector<char*> cargv;
        for (std::string& a : argv_) cargv.push_back(a.data());
        cargv.push_back(nullptr);

        pid_t pid = 0;
        const int rc = posix_spawnp(&pid, cargv[0], &actions, nullptr, cargv.data(), process_environ());
        posix_spawn_file_actions_destroy(&actions);
        close(out_pipe[1]);
        close(err_pipe[1]);

        if (rc != 0) {
            close(out_pipe[0]);
            close(err_pipe[0]);
            {
                std::lock_guard<std::mutex> lock(mutex_);
                status_.state = "failed";
                status_.last_error = "cannot start " + argv_[0] + ": " + std::strerror(rc);
            }
            log::error("cannot start event source: " + argv_[0]);
            if (wait_for_stop(backoff)) return;
            backoff = std::min(backoff * 2, max_backoff_ms_);
            continue;
        }

        service_.set_extra_ignored_pid(static_cast<int>(pid));
        const auto started = std::chrono::steady_clock::now();
        std::string buffer;
        std::string err_text;
        bool discarding = false;
        bool out_open = true;
        bool err_open = true;
        bool got_running = false;
        bool stopping = false;
        char chunk[65536];

        while (out_open || err_open) {
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (stop_) {
                    stopping = true;
                    break;
                }
            }
            pollfd fds[2];
            nfds_t n = 0;
            int out_idx = -1, err_idx = -1;
            if (out_open) {
                fds[n] = {out_pipe[0], POLLIN, 0};
                out_idx = static_cast<int>(n++);
            }
            if (err_open) {
                fds[n] = {err_pipe[0], POLLIN, 0};
                err_idx = static_cast<int>(n++);
            }
            const int pr = poll(fds, n, 300);
            if (pr < 0 && errno != EINTR) break;

            if (!got_running &&
                std::chrono::steady_clock::now() - started > std::chrono::milliseconds(1500)) {
                got_running = true;
                set_state("running");
            }
            if (pr <= 0) continue;

            if (out_idx >= 0 && (fds[out_idx].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
                const ssize_t r = read(out_pipe[0], chunk, sizeof(chunk));
                if (r > 0) {
                    if (!got_running) {
                        got_running = true;
                        set_state("running");
                    }
                    buffer.append(chunk, static_cast<std::size_t>(r));
                    std::size_t start = 0;
                    while (true) {
                        const std::size_t nl = buffer.find('\n', start);
                        if (nl == std::string::npos) break;
                        if (!discarding && nl > start) handle_line(buffer.substr(start, nl - start));
                        discarding = false;
                        start = nl + 1;
                    }
                    buffer.erase(0, start);
                    if (buffer.size() > kMaxLine) {
                        buffer.clear();
                        discarding = true;
                    }
                } else if (r == 0 || (errno != EINTR && errno != EAGAIN)) {
                    out_open = false;
                }
            }
            if (err_idx >= 0 && (fds[err_idx].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
                const ssize_t r = read(err_pipe[0], chunk, sizeof(chunk));
                if (r > 0) {
                    err_text.append(chunk, static_cast<std::size_t>(r));
                    if (err_text.size() > 8192) err_text.erase(0, err_text.size() - 4096);
                } else if (r == 0 || (errno != EINTR && errno != EAGAIN)) {
                    err_open = false;
                }
            }
        }

        close(out_pipe[0]);
        close(err_pipe[0]);

        int wstatus = 0;
        bool reaped = false;
        if (stopping) kill(pid, SIGTERM);
        for (int i = 0; i < 40 && !reaped; ++i) {
            const pid_t w = waitpid(pid, &wstatus, WNOHANG);
            if (w == pid || (w < 0 && errno != EINTR)) {
                reaped = true;
                break;
            }
            usleep(50 * 1000);
            if (i == 20) kill(pid, SIGKILL);
        }
        if (!reaped) {
            kill(pid, SIGKILL);
            waitpid(pid, &wstatus, 0);
        }
        service_.set_extra_ignored_pid(0);
        if (stopping) return;

        const auto alive_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started).count();
        std::string reason;
        if (WIFEXITED(wstatus)) {
            reason = "exited with code " + std::to_string(WEXITSTATUS(wstatus));
        } else if (WIFSIGNALED(wstatus)) {
            reason = "killed by signal " + std::to_string(WTERMSIG(wstatus));
        } else {
            reason = "ended";
        }
        std::string msg = argv_[0] + " " + reason;
        const std::string tail = last_line(err_text);
        if (!tail.empty()) msg += ": " + tail;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            status_.state = "failed";
            status_.last_error = msg;
        }
        log::warn("event source stopped: " + msg);

        if (alive_ms > 10000) backoff = initial_backoff_ms_;
        if (wait_for_stop(backoff)) return;
        backoff = std::min(backoff * 2, max_backoff_ms_);
    }
}

}
