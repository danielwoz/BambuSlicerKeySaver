// LAN printer discovery (SSDP) + BambuStudio access-code lookup.
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "host/lan_discover.hpp"

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <regex>
#include <set>

namespace bbl {

// Return the value of a case-insensitive "Key: value" line from an SSDP message.
static std::string ssdp_field(const std::string& msg, const char* key) {
    const size_t klen = std::strlen(key);
    for (size_t i = 0; i < msg.size();) {
        size_t eol = msg.find('\n', i);
        size_t linelen = (eol == std::string::npos ? msg.size() : eol) - i;
        size_t colon = msg.find(':', i);
        if (colon != std::string::npos && colon < i + linelen && colon - i == klen) {
            bool eq = true;
            for (size_t j = 0; j < klen; ++j)
                if (std::tolower((unsigned char)msg[i + j]) != std::tolower((unsigned char)key[j])) { eq = false; break; }
            if (eq) {
                size_t vs = colon + 1;
                size_t ve = i + linelen;
                while (vs < ve && (msg[vs] == ' ' || msg[vs] == '\t')) ++vs;
                while (ve > vs && (msg[ve - 1] == ' ' || msg[ve - 1] == '\t' || msg[ve - 1] == '\r')) --ve;
                return msg.substr(vs, ve - vs);
            }
        }
        if (eol == std::string::npos) break;
        i = eol + 1;
    }
    return "";
}

std::vector<LanPrinter> discover_lan_printers(int timeout_s) {
    std::vector<LanPrinter> out;
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return out;
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { WSACleanup(); return out; }
    BOOL reuse = TRUE;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof reuse);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(2021);
    if (bind(s, (sockaddr*)&addr, sizeof addr) != 0) { closesocket(s); WSACleanup(); return out; }
    ip_mreq mreq{};
    mreq.imr_multiaddr.s_addr = inet_addr("239.255.255.250");
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    setsockopt(s, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof mreq);
    DWORD to = 1500;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof to);

    const ULONGLONG deadline = GetTickCount64() + (ULONGLONG)(timeout_s < 1 ? 1 : timeout_s) * 1000;
    std::set<std::string> seen;
    char buf[4096];
    while (GetTickCount64() < deadline) {
        sockaddr_in from{};
        int fl = sizeof from;
        int n = recvfrom(s, buf, (int)sizeof buf - 1, 0, (sockaddr*)&from, &fl);
        if (n <= 0) continue;
        buf[n] = 0;
        std::string msg(buf, (size_t)n);
        std::string usn = ssdp_field(msg, "USN");
        if (usn.empty()) continue;
        if (usn.rfind("FFFF", 0) == 0) continue;   // virtual device
        if (seen.count(usn)) continue;
        std::string loc = ssdp_field(msg, "Location");
        if (loc.empty()) {
            char ips[64] = {0};
            inet_ntop(AF_INET, &from.sin_addr, ips, sizeof ips);
            loc = ips;
        }
        std::string name = ssdp_field(msg, "DevName.bambu.com");
        seen.insert(usn);
        out.push_back(LanPrinter{usn, loc, name.empty() ? usn : name});
    }
    closesocket(s);
    WSACleanup();
    return out;
}

std::map<std::string, std::string> read_studio_access_codes() {
    std::map<std::string, std::string> codes;
    const char* appdata = std::getenv("APPDATA");
    if (!appdata) return codes;
    std::string path = std::string(appdata) + "\\BambuStudio\\BambuStudio.conf";
    FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return codes;
    std::string raw;
    char b[8192];
    size_t n;
    while ((n = std::fread(b, 1, sizeof b, f)) > 0) raw.append(b, n);
    std::fclose(f);

    // The file is a JSON object with an "# MD5 checksum" trailer. Locate the
    // "access_code" object and brace-match its bounds (ignoring braces in strings).
    size_t key = raw.find("\"access_code\"");
    if (key == std::string::npos) return codes;
    size_t start = raw.find('{', key);
    if (start == std::string::npos) return codes;
    int depth = 0;
    bool instr = false;
    size_t end = std::string::npos;
    for (size_t i = start; i < raw.size(); ++i) {
        char c = raw[i];
        if (instr) {
            if (c == '"' && raw[i - 1] != '\\') instr = false;
        } else if (c == '"') {
            instr = true;
        } else if (c == '{') {
            ++depth;
        } else if (c == '}') {
            if (--depth == 0) { end = i; break; }
        }
    }
    if (end == std::string::npos) return codes;
    std::string section = raw.substr(start, end - start + 1);

    // Extract "serial" : "code" string pairs.
    std::regex pair_re("\"([^\"]+)\"\\s*:\\s*\"([^\"]+)\"");
    for (auto it = std::sregex_iterator(section.begin(), section.end(), pair_re);
         it != std::sregex_iterator(); ++it) {
        codes[(*it)[1].str()] = (*it)[2].str();
    }
    return codes;
}

}  // namespace bbl
