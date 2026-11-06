#include "behavior/rules.h"

// Built-in macOS-oriented behaviour rules. The JSON is split into several literals because MSVC
// limits a single string literal to ~16K characters.
//
// Tags carry the attack-chain state forward (children inherit them):
//   initial_access / downloaded_exec / downloader / staged   -> intrusion
//   persistence                                               -> foothold
//   c2_candidate / c2_beacon / c2_ioc / reverse_shell         -> command and control
// Rules that need an earlier stage use requires_tag_any, so the same connection scores higher
// when it follows suspicious activity.

namespace sec::behavior {

namespace {

const char* const kHead = R"JSON({
  "thresholds": { "warn": 60, "critical": 100 },
  "tag_window_s": 900,
  "rules": [
    {
      "id": "mac.exec.unsigned_from_tmp",
      "title": "임시 폴더에서 서명되지 않은 프로그램 실행",
      "event": "exec", "score": 40, "tag": "staged", "technique": "T1204.002",
      "when": {
        "path_prefix_any": ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/dev/shm/"],
        "unsigned_process": true
      }
    },
    {
      "id": "mac.exec.unsigned_from_downloads",
      "title": "다운로드 폴더에서 서명되지 않은 프로그램 실행",
      "event": "exec", "score": 30, "tag": "downloaded_exec", "technique": "T1204.002",
      "when": { "path_contains_any": ["/downloads/"], "unsigned_process": true }
    },
    {
      "id": "mac.exec.recent_download",
      "title": "방금 내려받은 서명되지 않은 파일 실행",
      "event": "exec", "score": 40, "tag": "downloaded_exec", "technique": "T1204.002",
      "when": { "requires_feature_any": ["recent_download_exec"], "unsigned_process": true }
    },
    {
      "id": "mac.exec.unsigned_from_shared",
      "title": "공유 폴더(/Users/Shared)에서 서명되지 않은 프로그램 실행",
      "event": "exec", "score": 35, "tag": "staged", "technique": "T1036",
      "when": { "path_prefix_any": ["/users/shared/"], "unsigned_process": true }
    },
    {
      "id": "mac.exec.shell_from_app",
      "title": "문서/브라우저 앱이 셸·스크립트 인터프리터를 실행",
      "event": "exec", "score": 50, "tag": "initial_access", "technique": "T1566.001",
      "when": {
        "parent_name_any": ["microsoft word", "microsoft excel", "microsoft powerpoint", "preview",
                            "safari", "google chrome", "firefox", "mail", "pages", "numbers", "keynote"],
        "name_any": ["sh", "bash", "zsh", "osascript", "python", "python3", "perl", "ruby", "curl", "wget"]
      }
    },
    {
      "id": "mac.exec.curl_pipe_shell",
      "title": "원격 스크립트를 내려받아 바로 셸로 실행 (curl | sh)",
      "event": "exec", "score": 50, "tag": "initial_access", "technique": "T1059.004",
      "when": {
        "name_any": ["sh", "bash", "zsh"],
        "args_all_of_any": [["curl", "wget"], ["| sh", "|sh", "| bash", "|bash", "| zsh", "|zsh"]]
      }
    },
    {
      "id": "mac.exec.downloader_to_tmp",
      "title": "curl/wget으로 임시 경로에 파일 저장",
      "event": "exec", "score": 25, "tag": "downloader", "technique": "T1105",
      "when": {
        "name_any": ["curl", "wget"],
        "args_contains_any": ["/tmp/", "/var/tmp/", "/users/shared/", "/dev/shm/"]
      }
    },
    {
      "id": "mac.exec.quarantine_removal",
      "title": "다운로드 격리 속성(com.apple.quarantine) 제거",
      "event": "exec", "score": 40, "tag": "defense_evasion", "technique": "T1553.001",
      "when": {
        "name_any": ["xattr"],
        "args_all_of_any": [["com.apple.quarantine", "-cr", "-rc"], ["-d", "-c", "-cr", "-rc", "-dr"]]
      }
    },
    {
      "id": "mac.exec.chmod_exec_in_staging",
      "title": "임시/다운로드 경로의 파일에 실행 권한 부여",
      "event": "exec", "score": 20, "tag": "staged", "technique": "T1222.002",
      "when": {
        "name_any": ["chmod"],
        "args_all_of_any": [["+x", "755", "777", "700", "775"],
                            ["/tmp/", "/var/tmp/", "/users/shared/", "/downloads/"]]
      }
    },
    {
      "id": "mac.exec.osascript_shell",
      "title": "AppleScript로 셸 명령 실행",
      "event": "exec", "score": 25, "technique": "T1059.002",
      "when": { "name_any": ["osascript"], "args_contains_any": ["do shell script"] }
    },
    {
      "id": "mac.exec.osascript_admin_prompt",
      "title": "AppleScript로 관리자 권한 요청",
      "event": "exec", "score": 40, "tag": "priv_esc", "technique": "T1548.004",
      "when": { "name_any": ["osascript"], "args_contains_any": ["with administrator privileges"] }
    },
    {
      "id": "mac.exec.gatekeeper_disable",
      "title": "Gatekeeper 비활성화 시도",
      "event": "exec", "score": 60, "tag": "defense_evasion", "technique": "T1562.001",
      "when": { "name_any": ["spctl"], "args_contains_any": ["--master-disable", "--global-disable"] }
    },
    {
      "id": "mac.exec.tcc_database_edit",
      "title": "TCC 권한 데이터베이스 직접 조작",
      "event": "exec", "score": 60, "tag": "priv_esc", "technique": "T1548",
      "when": { "name_any": ["sqlite3"], "args_contains_any": ["tcc.db"] }
    },
    {
      "id": "mac.exec.log_erase",
      "title": "시스템 로그 삭제",
      "event": "exec", "score": 40, "tag": "defense_evasion", "technique": "T1070.002",
      "when": { "name_any": ["log"], "args_contains_any": [" erase"] }
    },
    {
      "id": "mac.exec.backup_tamper",
      "title": "Time Machine 백업/스냅샷 삭제 또는 비활성화",
      "event": "exec", "score": 40, "tag": "impact", "technique": "T1490",
      "when": { "name_any": ["tmutil"], "args_contains_any": ["disable", "deletelocalsnapshots", "delete "] }
    },
    {
      "id": "mac.exec.keychain_dump",
      "title": "키체인 암호 추출 시도",
      "event": "exec", "score": 50, "tag": "credential_access", "technique": "T1555.001",
      "when": {
        "name_any": ["security"],
        "args_all_of_any": [["dump-keychain", "find-generic-password", "find-internet-password"],
                            ["dump-keychain", " -w", " -g"]]
      }
    },
    {
      "id": "mac.exec.reverse_shell_args",
      "title": "리버스 셸 명령 패턴",
      "event": "exec", "score": 70, "tag": "reverse_shell", "technique": "T1059.004",
      "when": {
        "args_contains_any": ["/dev/tcp/", "/dev/udp/", "bash -i >&", "nc -e", "ncat -e", "nc -c ", "mkfifo /tmp"]
      }
    },
    {
      "id": "mac.persist.launchctl_after_staging",
      "title": "의심 활동 이후 launchctl로 서비스 등록",
      "event": "exec", "score": 30, "tag": "persistence", "technique": "T1543.001",
      "when": {
        "name_any": ["launchctl"],
        "args_contains_any": ["load", "bootstrap", "submit", "enable"],
        "requires_tag_any": ["staged", "downloaded_exec", "initial_access", "downloader"]
      }
    },
)JSON";

const char* const kPersistence = R"JSON(
    {
      "id": "mac.persist.launchd_plist_unsigned",
      "title": "서명되지 않은 프로그램이 LaunchAgent/Daemon 등록",
      "event": "file", "score": 50, "tag": "persistence", "technique": "T1543.001",
      "when": {
        "file_path_contains_any": ["/library/launchagents/", "/library/launchdaemons/"],
        "file_ext_any": ["plist"],
        "unsigned_process": true
      }
    },
    {
      "id": "mac.persist.launchd_plist_script",
      "title": "스크립트/다운로더가 LaunchAgent/Daemon 등록",
      "event": "file", "score": 50, "tag": "persistence", "technique": "T1543.001",
      "when": {
        "file_path_contains_any": ["/library/launchagents/", "/library/launchdaemons/"],
        "file_ext_any": ["plist"],
        "name_any": ["sh", "bash", "zsh", "python", "python3", "perl", "ruby", "osascript", "curl", "wget"]
      }
    },
    {
      "id": "mac.persist.launchd_plist_after_staging",
      "title": "의심 활동 이후 LaunchAgent/Daemon 등록",
      "event": "file", "score": 30, "tag": "persistence", "technique": "T1543.001",
      "when": {
        "file_path_contains_any": ["/library/launchagents/", "/library/launchdaemons/"],
        "file_ext_any": ["plist"],
        "requires_tag_any": ["staged", "downloaded_exec", "initial_access", "downloader"]
      }
    },
    {
      "id": "mac.persist.shell_profile_unsigned",
      "title": "서명되지 않은 프로그램이 셸 시작 파일 수정",
      "event": "file", "score": 40, "tag": "persistence", "technique": "T1546.004",
      "when": {
        "file_name_any": [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bash_profile", ".bashrc", ".profile"],
        "unsigned_process": true
      }
    },
    {
      "id": "mac.persist.shell_profile_script",
      "title": "스크립트/다운로더가 셸 시작 파일 수정",
      "event": "file", "score": 40, "tag": "persistence", "technique": "T1546.004",
      "when": {
        "file_name_any": [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".bash_profile", ".bashrc", ".profile"],
        "name_any": ["curl", "wget", "python", "python3", "perl", "ruby", "osascript"]
      }
    },
    {
      "id": "mac.persist.cron_tab",
      "title": "cron 작업 등록",
      "event": "file", "score": 40, "tag": "persistence", "technique": "T1053.003",
      "when": { "file_path_prefix_any": ["/private/var/at/tabs/", "/var/at/tabs/"] }
    },
    {
      "id": "mac.persist.login_item",
      "title": "서명되지 않은 프로그램이 로그인 항목 등록",
      "event": "file", "score": 40, "tag": "persistence", "technique": "T1547.015",
      "when": {
        "file_path_contains_any": ["/com.apple.backgroundtaskmanagementagent/", "sharedfilelist/com.apple.LSSharedFileList"],
        "unsigned_process": true
      }
    },
    {
      "id": "mac.persist.sudoers",
      "title": "sudoers 설정 변경",
      "event": "file", "score": 60, "tag": "priv_esc", "technique": "T1548.003",
      "when": { "file_path_prefix_any": ["/private/etc/sudoers", "/etc/sudoers"], "name_not_any": ["sudo", "visudo"] }
    },
)JSON";

const char* const kNetwork = R"JSON(
    {
      "id": "mac.net.after_staging",
      "title": "의심 활동 이후 외부 서버와 통신",
      "event": "net", "score": 40, "tag": "c2_candidate", "technique": "T1071.001",
      "when": {
        "remote_public": true,
        "requires_tag_any": ["staged", "downloaded_exec", "initial_access", "downloader", "persistence", "defense_evasion"]
      }
    },
    {
      "id": "mac.net.unsigned_public",
      "title": "서명되지 않은 프로그램이 외부 서버와 통신",
      "event": "net", "score": 15, "tag": "c2_candidate", "technique": "T1071",
      "when": { "remote_public": true, "unsigned_process": true }
    },
    {
      "id": "mac.net.unsigned_uncommon_port",
      "title": "서명되지 않은 프로그램이 비표준 포트로 외부 통신",
      "event": "net", "score": 20, "technique": "T1571",
      "when": {
        "remote_public": true,
        "unsigned_process": true,
        "port_not_any": [80, 443, 53, 853, 123, 22, 8080, 8443]
      }
    },
    {
      "id": "mac.net.beaconing",
      "title": "일정한 주기의 반복 접속 (비콘 패턴)",
      "event": "net", "score": 40, "tag": "c2_beacon", "technique": "T1071",
      "when": { "remote_public": true, "requires_feature_any": ["beaconing"] }
    },
    {
      "id": "mac.net.shell_connect",
      "title": "셸/네트워크 도구가 외부 서버에 직접 연결 (리버스 셸 의심)",
      "event": "net", "score": 70, "tag": "reverse_shell", "technique": "T1059.004",
      "when": {
        "remote_public": true,
        "name_any": ["sh", "bash", "zsh", "nc", "ncat", "socat", "telnet"]
      }
    },
    {
      "id": "mac.net.ioc_match",
      "title": "알려진 악성 IOC(IP/도메인)와 통신",
      "event": "net", "score": 100, "tag": "c2_ioc", "technique": "T1071",
      "when": { "requires_feature_any": ["ioc_match"] }
    },
    {
      "id": "mac.net.egress_violation",
      "title": "허용되지 않은 외부 목적지로 통신 (이그레스 정책 위반)",
      "event": "net", "score": 60, "tag": "c2_candidate", "technique": "T1048",
      "when": { "remote_public": true, "requires_feature_any": ["egress_violation"] }
    },
    {
      "id": "mac.dns.ioc_match",
      "title": "알려진 악성 도메인 조회",
      "event": "dns", "score": 100, "tag": "c2_ioc", "technique": "T1071.004",
      "when": { "requires_feature_any": ["ioc_match"] }
    },
    {
      "id": "mac.dns.dga_like",
      "title": "자동 생성된 것처럼 보이는 도메인 조회 (DGA 의심)",
      "event": "dns", "score": 30, "tag": "c2_candidate", "technique": "T1568.002",
      "when": { "requires_feature_any": ["dga_like"] }
    },
    {
      "id": "mac.dns.tunnel_like",
      "title": "DNS 터널링 형태의 조회",
      "event": "dns", "score": 40, "tag": "c2_candidate", "technique": "T1071.004",
      "when": { "requires_feature_any": ["tunnel_like"] }
    }
  ]
}
)JSON";

}

std::string default_rules_json() {
    std::string s;
    s.reserve(24000);
    s += kHead;
    s += kPersistence;
    s += kNetwork;
    return s;
}

}
