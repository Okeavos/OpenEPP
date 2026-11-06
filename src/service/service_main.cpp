// Windows service host for the Sec agent. Windows-only; not compiled on other platforms.
//
//   sec-service.exe --install     register as auto-start service "SecEPP"
//   sec-service.exe --uninstall   remove the service
//   sec-service.exe --console     run in the foreground (Ctrl+C to stop) - handy for debugging
//   (no args)                     started by the Service Control Manager

#include "agent/agent.h"
#include "common/log.h"
#include "common/util.h"

#include <windows.h>

#include <atomic>
#include <cstdio>
#include <cwchar>
#include <memory>
#include <string>
#include <thread>

namespace {

constexpr wchar_t kServiceName[] = L"SecEPP";
constexpr wchar_t kDisplayName[] = L"Sec EPP Agent";

SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status = {};
std::atomic<bool> g_stop{false};

void report_state(DWORD state, DWORD wait_hint_ms = 0) {
    static DWORD checkpoint = 1;
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwCurrentState = state;
    g_status.dwControlsAccepted = (state == SERVICE_START_PENDING) ? 0 : (SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN);
    g_status.dwWin32ExitCode = NO_ERROR;
    g_status.dwWaitHint = wait_hint_ms;
    g_status.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkpoint++;
    if (g_status_handle != nullptr) SetServiceStatus(g_status_handle, &g_status);
}

std::filesystem::path config_path() {
    return sec::AgentConfig::default_data_dir() / "sec.conf";
}

// Loads config, sets up logging and runs the agent until g_stop is set.
int run_agent() {
    sec::Config cfg;
    const bool have_cfg = cfg.load(config_path());

    sec::AgentConfig acfg = sec::AgentConfig::from_config(cfg);
    sec::log::set_level(sec::log::parse_level(cfg.get("log_level", "info"), sec::log::Level::Info));
    sec::log::set_file(acfg.data_dir / "logs" / "sec.log");
    if (!have_cfg) {
        sec::log::warn("config not found at " + sec::util::path_to_utf8(config_path()) + "; using defaults");
    }

    sec::Agent agent(acfg);
    if (!agent.initialize()) return 1;
    sec::log::info("agent started");
    agent.run(g_stop);
    sec::log::info("agent stopped");
    return 0;
}

DWORD WINAPI control_handler(DWORD control, DWORD, LPVOID, LPVOID) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            report_state(SERVICE_STOP_PENDING, 10000);
            g_stop = true;
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

void WINAPI service_main(DWORD, LPWSTR*) {
    g_status_handle = RegisterServiceCtrlHandlerExW(kServiceName, control_handler, nullptr);
    if (g_status_handle == nullptr) return;
    report_state(SERVICE_START_PENDING, 5000);
    sec::log::set_console(false);

    std::thread worker([] { run_agent(); });
    report_state(SERVICE_RUNNING);
    worker.join();
    report_state(SERVICE_STOPPED);
}

BOOL WINAPI console_handler(DWORD type) {
    if (type == CTRL_C_EVENT || type == CTRL_BREAK_EVENT || type == CTRL_CLOSE_EVENT) {
        g_stop = true;
        return TRUE;
    }
    return FALSE;
}

int install_service() {
    wchar_t exe[MAX_PATH] = {};
    if (GetModuleFileNameW(nullptr, exe, MAX_PATH) == 0) return 1;
    const std::wstring bin = L"\"" + std::wstring(exe) + L"\"";

    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (scm == nullptr) {
        std::fprintf(stderr, "OpenSCManager failed (%lu). Run as Administrator.\n", GetLastError());
        return 1;
    }
    SC_HANDLE svc = CreateServiceW(scm, kServiceName, kDisplayName, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
                                   SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, bin.c_str(), nullptr, nullptr, nullptr,
                                   nullptr, nullptr);
    if (svc == nullptr) {
        std::fprintf(stderr, "CreateService failed (%lu)\n", GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }
    SERVICE_DESCRIPTIONW desc = {const_cast<LPWSTR>(L"Sec endpoint protection agent (malware scanning).")};
    ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);
    std::puts("service installed. Start with: sc start SecEPP");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return 0;
}

int uninstall_service() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (scm == nullptr) return 1;
    SC_HANDLE svc = OpenServiceW(scm, kServiceName, DELETE | SERVICE_STOP);
    if (svc == nullptr) {
        std::fprintf(stderr, "OpenService failed (%lu)\n", GetLastError());
        CloseServiceHandle(scm);
        return 1;
    }
    SERVICE_STATUS st = {};
    ControlService(svc, SERVICE_CONTROL_STOP, &st);
    const BOOL ok = DeleteService(svc);
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    std::puts(ok ? "service removed" : "DeleteService failed");
    return ok ? 0 : 1;
}

}

int wmain(int argc, wchar_t** argv) {
    if (argc > 1) {
        const std::wstring a = argv[1];
        if (a == L"--install") return install_service();
        if (a == L"--uninstall") return uninstall_service();
        if (a == L"--console") {
            SetConsoleCtrlHandler(console_handler, TRUE);
            return run_agent();
        }
        std::fputs("usage: sec-service [--install | --uninstall | --console]\n", stderr);
        return 2;
    }

    wchar_t name[] = L"SecEPP";
    SERVICE_TABLE_ENTRYW table[] = {{name, service_main}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) {
        std::fputs("not started by the Service Control Manager; use --console to run interactively\n", stderr);
        return 1;
    }
    return 0;
}
