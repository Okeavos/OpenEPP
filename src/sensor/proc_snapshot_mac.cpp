// macOS: list running processes with libproc and look up their code signatures with the Security
// framework. Signing is read without full validation (kSecCSBasicValidateOnly), cached per image path.

#include "sensor/proc_snapshot.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>

#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

namespace sec::sensor {

namespace {

struct Signing {
    bool known = false;
    bool platform = false;
    std::string signing_id;
    std::string team_id;
};

std::string cf_to_string(CFTypeRef ref) {
    if (ref == nullptr || CFGetTypeID(ref) != CFStringGetTypeID()) return std::string();
    const CFStringRef s = static_cast<CFStringRef>(ref);
    const CFIndex max = CFStringGetMaximumSizeForEncoding(CFStringGetLength(s), kCFStringEncodingUTF8) + 1;
    std::vector<char> buf(static_cast<size_t>(max));
    if (!CFStringGetCString(s, buf.data(), max, kCFStringEncodingUTF8)) return std::string();
    return std::string(buf.data());
}

Signing lookup_signing(const std::string& path) {
    Signing out;
    CFStringRef cfpath = CFStringCreateWithCString(kCFAllocatorDefault, path.c_str(), kCFStringEncodingUTF8);
    if (cfpath == nullptr) return out;
    CFURLRef url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, cfpath, kCFURLPOSIXPathStyle, false);
    CFRelease(cfpath);
    if (url == nullptr) return out;

    SecStaticCodeRef code = nullptr;
    const OSStatus created = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    CFRelease(url);
    if (created != errSecSuccess || code == nullptr) return out;

    CFDictionaryRef info = nullptr;
    if (SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) == errSecSuccess && info != nullptr) {
        out.signing_id = cf_to_string(CFDictionaryGetValue(info, kSecCodeInfoIdentifier));
        out.team_id = cf_to_string(CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier));
        // An image without a signature has no identifier; that is a definite "unsigned", not "unknown".
        out.known = true;
        CFRelease(info);
    }

    if (out.known && !out.signing_id.empty()) {
        SecRequirementRef req = nullptr;
        if (SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &req) == errSecSuccess &&
            req != nullptr) {
            out.platform = SecStaticCodeCheckValidity(code, kSecCSBasicValidateOnly, req) == errSecSuccess;
            CFRelease(req);
        }
    }
    CFRelease(code);
    return out;
}

// KERN_PROCARGS2 layout: int argc, exec path, NUL padding, argc argument strings, then environment strings.
void read_args_env(int pid, std::vector<std::string>& args, std::vector<std::string>& env) {
    int mib[3] = {CTL_KERN, KERN_PROCARGS2, pid};
    size_t size = 0;
    if (sysctl(mib, 3, nullptr, &size, nullptr, 0) != 0 || size < sizeof(int)) return;
    std::vector<char> buf(size);
    if (sysctl(mib, 3, buf.data(), &size, nullptr, 0) != 0 || size < sizeof(int)) return;

    int argc = 0;
    std::memcpy(&argc, buf.data(), sizeof(int));
    size_t pos = sizeof(int);
    while (pos < size && buf[pos] != '\0') ++pos;  // exec path
    while (pos < size && buf[pos] == '\0') ++pos;  // padding

    auto next = [&](std::string& dst) {
        if (pos >= size) return false;
        size_t end = pos;
        while (end < size && buf[end] != '\0') ++end;
        dst.assign(buf.data() + pos, end - pos);
        pos = end + 1;
        return true;
    };

    std::string s;
    for (int i = 0; i < argc && i < 512; ++i) {
        if (!next(s)) return;
        args.push_back(s);
    }
    while (pos < size && env.size() < 16 && next(s)) {
        if (s.empty()) break;
        if (s.rfind("DYLD_", 0) == 0) env.push_back(s.size() > 512 ? s.substr(0, 512) : s);
    }
}

}

std::vector<behavior::ProcessRef> snapshot_processes() {
    std::vector<behavior::ProcessRef> out;
    const int bytes = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
    if (bytes <= 0) return out;
    std::vector<pid_t> pids(static_cast<size_t>(bytes) / sizeof(pid_t) + 64);
    const int got = proc_listpids(PROC_ALL_PIDS, 0, pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
    if (got <= 0) return out;
    pids.resize(static_cast<size_t>(got) / sizeof(pid_t));

    std::unordered_map<std::string, Signing> cache;
    for (const pid_t pid : pids) {
        if (pid <= 0) continue;
        char pathbuf[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) <= 0) continue;

        behavior::ProcessRef r;
        r.pid = static_cast<int>(pid);
        r.path = pathbuf;
        proc_bsdinfo bsd = {};
        if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, sizeof(bsd)) == static_cast<int>(sizeof(bsd))) {
            r.ppid = static_cast<int>(bsd.pbi_ppid);
        }
        read_args_env(static_cast<int>(pid), r.args, r.env);

        auto it = cache.find(r.path);
        if (it == cache.end()) it = cache.emplace(r.path, lookup_signing(r.path)).first;
        const Signing& sg = it->second;
        if (sg.known) {
            r.sig_known = true;
            r.platform_binary = sg.platform;
            r.signing_id = sg.signing_id;
            r.team_id = sg.team_id;
        }
        out.push_back(std::move(r));
    }
    return out;
}

}
