// A WinHTTP implementation of the obn::http interface (obn/http_client.hpp),
// used INSTEAD of the library's libcurl backend so the get_app_cert client
// (obn::appcert::fetch) builds against the OpenSSL already on the machine with no
// libcurl dependency. Sends ordered_headers verbatim and suppresses WinHTTP's
// default Accept so the request matches what the cloud expects for an
// authenticated GET.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>

#include "obn/http_client.hpp"

#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

namespace obn::http {

namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return std::wstring();
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

const wchar_t* method_verb(Method m) {
    switch (m) {
        case Method::GET:   return L"GET";
        case Method::POST:  return L"POST";
        case Method::PUT:   return L"PUT";
        case Method::DEL:   return L"DELETE";
        case Method::PATCH: return L"PATCH";
    }
    return L"GET";
}

}  // namespace

void global_init() {}  // WinHTTP needs no process-wide init.

Response perform(const Request& req) {
    Response r;

    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof(uc);
    wchar_t host[256] = {0}, path[4096] = {0};
    uc.lpszHostName = host;  uc.dwHostNameLength = _countof(host);
    uc.lpszUrlPath  = path;  uc.dwUrlPathLength  = _countof(path);
    // Keep the extra info (query string) attached to the path.
    std::wstring wurl = widen(req.url);
    if (!WinHttpCrackUrl(wurl.c_str(), (DWORD)wurl.size(), 0, &uc)) {
        r.error = "WinHttpCrackUrl failed"; return r;
    }
    const bool https = (uc.nScheme == INTERNET_SCHEME_HTTPS);
    INTERNET_PORT port = uc.nPort ? uc.nPort : (https ? 443 : 80);
    std::wstring full_path(path);
    if (uc.lpszExtraInfo && uc.dwExtraInfoLength) full_path.append(uc.lpszExtraInfo, uc.dwExtraInfoLength);

    HINTERNET session = WinHttpOpen(L"OBN/winhttp",
                                    WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) { r.error = "WinHttpOpen failed"; return r; }
    WinHttpSetTimeouts(session, req.connect_timeout_s * 1000, req.connect_timeout_s * 1000,
                       req.timeout_s * 1000, req.timeout_s * 1000);

    HINTERNET conn = WinHttpConnect(session, host, port, 0);
    if (!conn) { WinHttpCloseHandle(session); r.error = "WinHttpConnect failed"; return r; }

    DWORD flags = https ? WINHTTP_FLAG_SECURE : 0;
    // Pass NULL accept types so WinHTTP does not inject a default Accept header.
    HINTERNET hreq = WinHttpOpenRequest(conn, method_verb(req.method), full_path.c_str(),
                                        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hreq) { WinHttpCloseHandle(conn); WinHttpCloseHandle(session); r.error = "WinHttpOpenRequest failed"; return r; }

    if (req.insecure && https) {
        DWORD sec = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hreq, WINHTTP_OPTION_SECURITY_FLAGS, &sec, sizeof(sec));
    }

    // Build the header block. ordered_headers, when present, are sent verbatim in
    // this exact order/casing (the cloud fingerprints on order); otherwise the
    // sorted headers map is used.
    std::wstring hdrs;
    auto add = [&](const std::string& k, const std::string& v) {
        hdrs += widen(k); hdrs += L": "; hdrs += widen(v); hdrs += L"\r\n";
    };
    if (!req.ordered_headers.empty()) {
        for (const auto& kv : req.ordered_headers) add(kv.first, kv.second);
    } else {
        for (const auto& kv : req.headers) add(kv.first, kv.second);
    }

    const void* bodyp = req.body.empty() ? WINHTTP_NO_REQUEST_DATA : req.body.data();
    DWORD bodylen = (DWORD)req.body.size();
    BOOL sent = WinHttpSendRequest(hreq,
                                   hdrs.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : hdrs.c_str(),
                                   hdrs.empty() ? 0 : (DWORD)-1L,
                                   (LPVOID)bodyp, bodylen, bodylen, 0);
    if (!sent || !WinHttpReceiveResponse(hreq, nullptr)) {
        r.error = "WinHttp send/receive failed (" + std::to_string(GetLastError()) + ")";
        WinHttpCloseHandle(hreq); WinHttpCloseHandle(conn); WinHttpCloseHandle(session);
        return r;
    }

    DWORD status = 0, slen = sizeof(status);
    WinHttpQueryHeaders(hreq, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &slen, WINHTTP_NO_HEADER_INDEX);
    r.status_code = (long)status;

    // Content-Type (best-effort).
    {
        wchar_t ct[512] = {0}; DWORD ctl = sizeof(ct);
        if (WinHttpQueryHeaders(hreq, WINHTTP_QUERY_CONTENT_TYPE, WINHTTP_HEADER_NAME_BY_INDEX,
                                ct, &ctl, WINHTTP_NO_HEADER_INDEX)) {
            int n = WideCharToMultiByte(CP_UTF8, 0, ct, -1, nullptr, 0, nullptr, nullptr);
            if (n > 1) { r.content_type.resize(n - 1);
                WideCharToMultiByte(CP_UTF8, 0, ct, -1, &r.content_type[0], n, nullptr, nullptr); }
        }
    }

    // Body.
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hreq, &avail) || avail == 0) break;
        std::string chunk(avail, '\0');
        DWORD got = 0;
        if (!WinHttpReadData(hreq, &chunk[0], avail, &got) || got == 0) break;
        r.body.append(chunk.data(), got);
    }

    WinHttpCloseHandle(hreq); WinHttpCloseHandle(conn); WinHttpCloseHandle(session);
    return r;
}

Response get_json(const std::string& url, const std::map<std::string, std::string>& headers,
                  const std::string& ca_file) {
    Request req; req.method = Method::GET; req.url = url; req.headers = headers; req.ca_file = ca_file;
    req.headers["Accept"] = "application/json";
    return perform(req);
}

Response post_json(const std::string& url, const std::string& body,
                   const std::map<std::string, std::string>& headers, const std::string& ca_file) {
    Request req; req.method = Method::POST; req.url = url; req.body = body; req.headers = headers; req.ca_file = ca_file;
    req.headers["Content-Type"] = "application/json";
    return perform(req);
}

std::string url_encode(const std::string& in) {
    static const char* H = "0123456789ABCDEF";
    std::string o; o.reserve(in.size() * 3);
    for (unsigned char c : in) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') o += (char)c;
        else { o += '%'; o += H[c >> 4]; o += H[c & 0xF]; }
    }
    return o;
}

}  // namespace obn::http
