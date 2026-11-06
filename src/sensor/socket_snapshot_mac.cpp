// macOS: list established / connecting TCP sockets of all visible processes through libproc.
// Running as root sees every process; as a normal user only your own.

#include "sensor/socket_poller.h"

#include <arpa/inet.h>
#include <libproc.h>
#include <netinet/in.h>
#include <sys/proc_info.h>
#include <sys/socket.h>

#include <cstring>
#include <vector>

namespace sec::sensor {

namespace {

bool format_remote(const in_sockinfo& ini, std::string& ip) {
    char buf[INET6_ADDRSTRLEN] = {};
    if ((ini.insi_vflag & INI_IPV4) != 0) {
        in_addr a = ini.insi_faddr.ina_46.i46a_addr4;
        if (inet_ntop(AF_INET, &a, buf, sizeof(buf)) == nullptr) return false;
    } else if ((ini.insi_vflag & INI_IPV6) != 0) {
        in6_addr a = ini.insi_faddr.ina_6;
        if (inet_ntop(AF_INET6, &a, buf, sizeof(buf)) == nullptr) return false;
    } else {
        return false;
    }
    ip = buf;
    return true;
}

int port_of(int network_order_port) { return static_cast<int>(ntohs(static_cast<uint16_t>(network_order_port))); }

}

bool snapshot_tcp_connections_mac(std::vector<ConnInfo>& out) {
    const int bytes = proc_listpids(PROC_ALL_PIDS, 0, nullptr, 0);
    if (bytes <= 0) return false;

    std::vector<pid_t> pids(static_cast<size_t>(bytes) / sizeof(pid_t) + 64);
    const int got = proc_listpids(PROC_ALL_PIDS, 0, pids.data(), static_cast<int>(pids.size() * sizeof(pid_t)));
    if (got <= 0) return false;
    pids.resize(static_cast<size_t>(got) / sizeof(pid_t));

    std::vector<proc_fdinfo> fds;
    for (const pid_t pid : pids) {
        if (pid <= 0) continue;

        const int fd_bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
        if (fd_bytes <= 0) continue;
        fds.resize(static_cast<size_t>(fd_bytes) / sizeof(proc_fdinfo) + 16);
        const int fd_got = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.data(), static_cast<int>(fds.size() * sizeof(proc_fdinfo)));
        if (fd_got <= 0) continue;
        const size_t fd_count = static_cast<size_t>(fd_got) / sizeof(proc_fdinfo);

        bool info_loaded = false;
        int ppid = 0;
        std::string path;

        for (size_t i = 0; i < fd_count; ++i) {
            if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;

            socket_fdinfo si;
            std::memset(&si, 0, sizeof(si));
            if (proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &si, sizeof(si)) != static_cast<int>(sizeof(si))) {
                continue;
            }
            if (si.psi.soi_kind != SOCKINFO_TCP) continue;
            const tcp_sockinfo& tcp = si.psi.soi_proto.pri_tcp;
            if (tcp.tcpsi_state != TSI_S_ESTABLISHED && tcp.tcpsi_state != TSI_S_SYN_SENT) continue;

            std::string ip;
            if (!format_remote(tcp.tcpsi_ini, ip)) continue;
            const int rport = port_of(tcp.tcpsi_ini.insi_fport);
            if (rport <= 0) continue;

            if (!info_loaded) {
                info_loaded = true;
                proc_bsdinfo bsd;
                std::memset(&bsd, 0, sizeof(bsd));
                if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, sizeof(bsd)) == static_cast<int>(sizeof(bsd))) {
                    ppid = static_cast<int>(bsd.pbi_ppid);
                }
                char pathbuf[PROC_PIDPATHINFO_MAXSIZE] = {};
                if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) > 0) path = pathbuf;
            }

            ConnInfo c;
            c.pid = static_cast<int>(pid);
            c.ppid = ppid;
            c.path = path;
            c.remote_ip = ip;
            c.remote_port = rport;
            c.local_port = port_of(tcp.tcpsi_ini.insi_lport);
            out.push_back(std::move(c));
        }
    }
    return true;
}

}
