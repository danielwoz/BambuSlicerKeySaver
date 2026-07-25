// fake_broker2 — fake TLS+MQTT printer broker for the Windows port.
//
// Purpose: drive the plugin's enc_msg / security-command path so it populates
// device_pub_key_map[dev_id] with a printer RSA pubkey we generate, then encrypts
// param->param_enc and runs the slicer sign.
//
// Differences from fake_broker.cpp (the original):
//  * The cert_report is delivered on the plugin's OWN subscribe topic
//    device/<dev>/report (the plugin only subscribes to /report; it never
//    subscribes to /security), in the printer-style security-command shape
//    {"security":{"command":"cert_report","result":"success","reason":"success",
//     "sequence_id":"<n>","printer_cert":"<PEM>","dev_id":"<dev>"}}.
//  * The real 23 KB push_status report (BAMBU_FAKE_REPORT) is pushed on the
//    /report subscribe AND repeated, and its top-level "fun" field (parsed by
//    filter_security_flag to set enc-enable) is preserved. If the report is a
//    stub, we synthesise a report carrying "fun" + sec_link:1.
//  * A stable RSA-2048 keypair is used for the printer cert; the private key is
//    written out (--key-out) so param_enc could be decrypted for verification.
//  * The cert_report is sent BOTH reactively (when the plugin publishes an
//    app_cert / cert_request / security command) AND proactively (unsolicited,
//    shortly after the plugin subscribes) — belt and suspenders.
//
// Build: see win/broker/build2.sh

#include <winsock2.h>
#include <ws2tcpip.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static std::string g_dev_id = "01S00A2B3C4D5E6";
static SSL_CTX*    g_ctx     = nullptr;
static std::string g_cert_pem;       // printer leaf cert (PEM)
static std::string g_key_pem;        // printer private key (PEM)
static int         g_seq     = 5000; // security-command sequence counter

static void logln(const char* s) { std::fprintf(stderr, "[fake2] %s\n", s); std::fflush(stderr); }

static std::string load_file(const char* env) {
    const char* p = std::getenv(env);
    if (!p || !p[0]) return {};
    FILE* f = std::fopen(p, "rb");
    if (!f) { std::fprintf(stderr, "[fake2] %s open fail: %s\n", env, p); return {}; }
    std::string s; char buf[8192]; size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) s.append(buf, n);
    std::fclose(f);
    std::fprintf(stderr, "[fake2] loaded %s (%zu bytes) from %s\n", env, s.size(), p);
    return s;
}
static std::string g_real_report;

static void info_cb(const SSL* ssl, int where, int ret) {
    (void)ssl;
    if (where & SSL_CB_ALERT)
        std::fprintf(stderr, "[fake2] TLS ALERT %s: %s / %s\n",
                     (where & SSL_CB_READ) ? "recv" : "sent",
                     SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
}
static int accept_any_client_cert(int, X509_STORE_CTX*) { return 1; }

static bool gen_ctx() {
    g_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ctx) return false;
    SSL_CTX_set_info_callback(g_ctx, info_cb);
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    if (!pkey) return false;

    X509* cert = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365L * 24 * 3600);
    X509_set_version(cert, 2);
    X509_set_pubkey(cert, pkey);
    X509_NAME* name = X509_get_subject_name(cert);
    // Bambu LAN printer certs use CN = device serial.
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
        (const unsigned char*)g_dev_id.c_str(), -1, -1, 0);
    X509_set_issuer_name(cert, name);
    {
        std::string san = "DNS:" + g_dev_id + ",IP:127.0.0.1,DNS:localhost";
        X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name,
                                                  (char*)san.c_str());
        if (ext) { X509_add_ext(cert, ext, -1); X509_EXTENSION_free(ext); }
    }
    X509_sign(cert, pkey, EVP_sha256());

    // Serialise leaf cert PEM.
    { BIO* bio = BIO_new(BIO_s_mem()); PEM_write_bio_X509(bio, cert);
      char* d=nullptr; long n=BIO_get_mem_data(bio,&d); g_cert_pem.assign(d,(size_t)n); BIO_free(bio); }
    // Serialise private key PEM (PKCS#8) so param_enc could be decrypted.
    { BIO* bio = BIO_new(BIO_s_mem()); PEM_write_bio_PrivateKey(bio,pkey,nullptr,nullptr,0,nullptr,nullptr);
      char* d=nullptr; long n=BIO_get_mem_data(bio,&d); g_key_pem.assign(d,(size_t)n); BIO_free(bio); }

    if (SSL_CTX_use_certificate(g_ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey(g_ctx, pkey) != 1) {
        X509_free(cert); EVP_PKEY_free(pkey); return false;
    }
    const char* mtls = std::getenv("BAMBU_MTLS");
    if (mtls && mtls[0] == '1')
        SSL_CTX_set_verify(g_ctx, SSL_VERIFY_PEER, accept_any_client_cert);
    else
        SSL_CTX_set_verify(g_ctx, SSL_VERIFY_NONE, nullptr);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    return true;
}

static std::vector<uint8_t> encode_remaining(uint32_t v) {
    std::vector<uint8_t> out;
    do { uint8_t b = v & 0x7f; v >>= 7; out.push_back(v ? (b | 0x80) : b); } while (v);
    return out;
}
static bool ssl_write_all(SSL* ssl, const void* buf, size_t n) {
    size_t off = 0;
    while (off < n) { int w = SSL_write(ssl,(const char*)buf+off,(int)(n-off)); if (w<=0) return false; off+=(size_t)w; }
    return true;
}
static bool ssl_read_exact(SSL* ssl, void* buf, size_t n) {
    size_t off = 0;
    while (off < n) { int r = SSL_read(ssl,(char*)buf+off,(int)(n-off)); if (r<=0) return false; off+=(size_t)r; }
    return true;
}
static uint8_t read_packet(SSL* ssl, std::vector<uint8_t>& body) {
    uint8_t hdr;
    if (!ssl_read_exact(ssl, &hdr, 1)) return 0;
    uint32_t rem = 0; int shift = 0;
    for (int i = 0; i < 4; i++) {
        uint8_t b; if (!ssl_read_exact(ssl, &b, 1)) return 0;
        rem |= (uint32_t)(b & 0x7f) << shift; shift += 7;
        if (!(b & 0x80)) break;
    }
    body.resize(rem);
    if (rem > 0 && !ssl_read_exact(ssl, body.data(), rem)) return 0;
    return hdr;
}
static bool mqtt_publish(SSL* ssl, const std::string& topic, const std::string& payload) {
    uint16_t tlen = (uint16_t)topic.size();
    uint32_t rem = 2 + tlen + (uint32_t)payload.size();
    std::vector<uint8_t> pkt;
    pkt.push_back(0x30);
    for (uint8_t b : encode_remaining(rem)) pkt.push_back(b);
    pkt.push_back((uint8_t)(tlen >> 8));
    pkt.push_back((uint8_t)(tlen & 0xff));
    for (char c : topic)   pkt.push_back((uint8_t)c);
    for (char c : payload) pkt.push_back((uint8_t)c);
    return ssl_write_all(ssl, pkt.data(), pkt.size());
}

// JSON-escape a PEM (newlines + quotes) for embedding in a JSON string value.
static std::string json_escape(const std::string& pem) {
    std::string out; out.reserve(pem.size() + 64);
    for (char c : pem) {
        if (c == '\n') out += "\\n";
        else if (c == '\r') out += "";
        else if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else out += c;
    }
    return out;
}

// Build a cert_report security command carrying our printer cert PEM. Multiple
// field spellings are included so whichever the plugin's mqtt_cmd_cert_report
// looks for is present: printer_cert (confirmed from strings), plus cert/dev_id.
static std::string make_cert_report(const std::string& echo_seq) {
    std::string esc = json_escape(g_cert_pem);
    std::string seq = echo_seq;
    if (seq.empty()) { char seqbuf[16]; std::snprintf(seqbuf, sizeof seqbuf, "%d", g_seq++); seq = seqbuf; }
    // Command value: the plugin's receive-dispatcher matches "app_cert_install"
    // (the only cert command VALUE present in the string table; "cert_report" is
    // only the handler's log name). Env BAMBU_CERT_CMD overrides for probing.
    const char* cmd = std::getenv("BAMBU_CERT_CMD");
    if (!cmd || !cmd[0]) cmd = "app_cert_install";
    std::string s =
        "{\"security\":{"
        "\"command\":\"" + std::string(cmd) + "\","
        "\"sequence_id\":\"" + seq + "\","
        "\"result\":\"success\","
        "\"reason\":\"success\","
        "\"err_code\":0,"
        "\"dev_id\":\"" + g_dev_id + "\","
        "\"printer_cert\":\"" + esc + "\""
        "}}";
    return s;
}

// Extract the value of "sequence_id":"..." from a payload (first occurrence).
static std::string extract_seq(const std::string& pl) {
    const std::string key = "\"sequence_id\":\"";
    size_t p = pl.find(key);
    if (p == std::string::npos) return {};
    p += key.size();
    size_t e = pl.find('"', p);
    if (e == std::string::npos) return {};
    return pl.substr(p, e - p);
}

// A push_status report that carries the security-enable signal. Prefer the real
// 23 KB report (has "fun"); otherwise synthesise one with fun + sec_link:1.
static std::string make_report() {
    if (!g_real_report.empty()) return g_real_report;
    return
        "{\"print\":{\"command\":\"push_status\",\"sequence_id\":\"0\","
        "\"result\":\"success\",\"fun\":\"4035FF1AFFF9CB7\",\"fun2\":\"1177\","
        "\"sec_link\":1,"
        "\"online\":{\"ahb\":true,\"rfid\":true,\"version\":2},"
        "\"home_flag\":0,\"mc_print_stage\":\"1\"}}";
}

static void handle_client(SSL* ssl) {
    const std::string report_topic = "device/" + g_dev_id + "/report";
    bool conn_sent = false;
    int  cert_reports_sent = 0;
    bool report_pushed = false;
    while (true) {
        std::vector<uint8_t> body;
        uint8_t hdr = read_packet(ssl, body);
        if (!hdr) break;
        uint8_t type = hdr >> 4;
        if (type == 1) {                       // CONNECT
            uint8_t connack[4] = {0x20, 0x02, 0x00, 0x00};
            ssl_write_all(ssl, connack, 4);
            conn_sent = true;
            logln("MQTT CONNECT accepted");
        } else if (type == 8 && conn_sent) {   // SUBSCRIBE
            if (body.size() >= 5) {
                uint16_t pid = ((uint16_t)body[0] << 8) | body[1];
                uint8_t suback[5] = {0x90, 0x03, (uint8_t)(pid >> 8), (uint8_t)(pid & 0xff), 0x00};
                ssl_write_all(ssl, suback, 5);
                uint16_t tl = ((uint16_t)body[2] << 8) | body[3];
                std::string topic;
                if ((size_t)(4 + tl) <= body.size()) topic.assign(body.begin()+4, body.begin()+4+tl);
                std::fprintf(stderr, "[fake2] SUBSCRIBE topic='%s'\n", topic.c_str());
                if (topic.find("/report") != std::string::npos) {
                    // 1) push the real/status report (enables enc via "fun").
                    std::string rep = make_report();
                    mqtt_publish(ssl, report_topic, rep);
                    report_pushed = true;
                    std::fprintf(stderr, "[fake2] pushed %s report (%zu bytes) to %s\n",
                                 g_real_report.empty() ? "SYNTH" : "REAL", rep.size(), report_topic.c_str());
                    // NB: no proactive/unsolicited cert_report here — the plugin
                    // rejects a cert_report whose sequence_id doesn't match the
                    // pending app_cert_install request (msgID 400 security_seq
                    // mismatch). We ONLY reply reactively, echoing the exact
                    // request sequence_id (see the PUBLISH handler below).
                }
            }
        } else if (type == 3 && conn_sent) {   // PUBLISH from plugin
            if (body.size() < 2) continue;
            uint16_t tlen = ((uint16_t)body[0] << 8) | body[1];
            if ((size_t)(2 + tlen) > body.size()) continue;
            std::string topic(body.begin() + 2, body.begin() + 2 + tlen);
            size_t off = 2 + tlen;
            if ((hdr & 0x06) != 0) off += 2;  // skip packet id for QoS>0
            std::string pl(body.begin() + (off <= body.size() ? off : body.size()), body.end());
            std::fprintf(stderr, "[fake2] PUBLISH topic='%s' payload[%zu]: %.*s\n",
                         topic.c_str(), pl.size(),
                         (int)(pl.size() > 200 ? 200 : pl.size()), pl.c_str());
            std::fflush(stderr);
            // Dump the FULL first few security publishes to a file for offline
            // analysis of the exact app_cert / cert_request shape the plugin uses.
            if (pl.find("app_cert") != std::string::npos ||
                pl.find("\"security\"") != std::string::npos) {
                static int dumped = 0;
                if (dumped < 3) {
                    const char* dp = std::getenv("BAMBU_SEC_DUMP");
                    if (dp && dp[0]) {
                        char path[512]; std::snprintf(path, sizeof path, "%s.%d", dp, dumped);
                        FILE* df = std::fopen(path, "wb");
                        if (df) { std::fwrite(pl.data(),1,pl.size(),df); std::fclose(df);
                                  std::fprintf(stderr, "[fake2] dumped security publish #%d (%zu bytes) -> %s\n",
                                               dumped, pl.size(), path); }
                    }
                    dumped++;
                }
            }
            // Dump the FULL first print-sign publishes (carry sign_string) so the
            // signature can be validated offline (s^e mod N -> PKCS#1 structure).
            if (pl.find("sign_string") != std::string::npos) {
                static int sdumped = 0;
                if (sdumped < 3) {
                    const char* sp = std::getenv("BAMBU_SIGN_DUMP");
                    if (sp && sp[0]) {
                        char path[512]; std::snprintf(path, sizeof path, "%s.%d", sp, sdumped);
                        FILE* sf = std::fopen(path, "wb");
                        if (sf) { std::fwrite(pl.data(),1,pl.size(),sf); std::fclose(sf);
                                  std::fprintf(stderr, "[fake2] dumped SIGN publish #%d (%zu bytes) -> %s\n",
                                               sdumped, pl.size(), path); }
                    }
                    sdumped++;
                }
            }

            // PUBACK for QoS1.
            if ((hdr & 0x06) == 0x02 && body.size() >= (size_t)(2 + tlen + 2)) {
                uint16_t pid = ((uint16_t)body[2 + tlen] << 8) | body[3 + tlen];
                uint8_t puback[4] = {0x40, 0x02, (uint8_t)(pid >> 8), (uint8_t)(pid & 0xff)};
                ssl_write_all(ssl, puback, 4);
            }

            // Reactive cert_report: the plugin publishes a security/app_cert /
            // cert_request command when it needs the device pubkey. Reply with a
            // cert_report on /report. Resend on EVERY such publish (the plugin
            // may retry). Also (re)send if it publishes a print.* while the map
            // is still empty (in case our proactive one was too early).
            // Reply ONLY to an actual app_cert_install / cert_request publish,
            // echoing that request's exact sequence_id (the plugin's
            // mqtt_cmd_cert_report matches sequence_int against the pending
            // request; a mismatch -> msgID 400 reject). Do NOT reply to plain
            // print.* or push publishes.
            bool is_sec_req = pl.find("app_cert") != std::string::npos ||
                              pl.find("cert_request") != std::string::npos;
            if (is_sec_req) {
                std::string echo = extract_seq(pl);
                std::string cr = make_cert_report(echo);
                mqtt_publish(ssl, report_topic, cr);
                cert_reports_sent++;
                std::fprintf(stderr, "[fake2] cert_report #%d injected (%zu bytes, echo_seq=%s) -> %s\n",
                             cert_reports_sent, cr.size(), echo.empty()?"(none)":echo.c_str(),
                             report_topic.c_str());
                std::fflush(stderr);
            }
            // Keep the device "online": re-push the status report after each
            // /request so the plugin keeps enc enabled.
            if (topic.find("/request") != std::string::npos && report_pushed) {
                std::string rep = make_report();
                mqtt_publish(ssl, report_topic, rep);
            }
        } else if (type == 12) {               // PINGREQ
            uint8_t pingresp[2] = {0xd0, 0x00};
            ssl_write_all(ssl, pingresp, 2);
        } else if (type == 14) {               // DISCONNECT
            logln("MQTT DISCONNECT"); break;
        } else {
            std::fprintf(stderr, "[fake2] MQTT packet type=%u (ignored)\n", type);
        }
    }
}

int main(int argc, char** argv) {
    unsigned short port = 8883;
    const char* cert_out = nullptr;
    const char* key_out  = nullptr;
    for (int i = 1; i + 1 < argc; ++i) {
        if (!std::strcmp(argv[i], "--dev-id")) g_dev_id = argv[i + 1];
        else if (!std::strcmp(argv[i], "--port")) port = (unsigned short)atoi(argv[i + 1]);
        else if (!std::strcmp(argv[i], "--cert-out")) cert_out = argv[i + 1];
        else if (!std::strcmp(argv[i], "--key-out"))  key_out  = argv[i + 1];
    }

    g_real_report = load_file("BAMBU_FAKE_REPORT");

    WSADATA w;
    if (WSAStartup(MAKEWORD(2, 2), &w) != 0) { logln("WSAStartup failed"); return 1; }
    if (!gen_ctx()) { logln("gen_ctx failed"); return 1; }

    if (cert_out) {
        FILE* f = std::fopen(cert_out, "wb");
        if (f) { std::fwrite(g_cert_pem.data(),1,g_cert_pem.size(),f); std::fclose(f);
                 std::fprintf(stderr,"[fake2] wrote printer cert to %s\n",cert_out); }
    }
    if (key_out) {
        FILE* f = std::fopen(key_out, "wb");
        if (f) { std::fwrite(g_key_pem.data(),1,g_key_pem.size(),f); std::fclose(f);
                 std::fprintf(stderr,"[fake2] wrote printer key to %s\n",key_out); }
    }

    SOCKET srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET) { logln("socket failed"); return 1; }
    BOOL on = TRUE; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char*)&on, sizeof(on));
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
    InetPtonA(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(srv, (sockaddr*)&a, sizeof(a)) != 0) {
        std::fprintf(stderr, "[fake2] bind 127.0.0.1:%u failed (err=%d)\n", port, WSAGetLastError());
        return 1;
    }
    if (listen(srv, 4) != 0) { logln("listen failed"); return 1; }

    std::fprintf(stderr, "[fake2] READY dev_id=%s port=%u\n", g_dev_id.c_str(), port);
    std::fflush(stderr);
    std::printf("READY\n"); std::fflush(stdout);

    for (;;) {
        sockaddr_in peer{}; int plen = sizeof(peer);
        SOCKET c = accept(srv, (sockaddr*)&peer, &plen);
        if (c == INVALID_SOCKET) break;
        SSL* ssl = SSL_new(g_ctx);
        SSL_set_fd(ssl, (int)c);
        if (SSL_accept(ssl) == 1) {
            logln("TLS accepted");
            X509* pc = SSL_get_peer_certificate(ssl);
            if (pc) { logln("*** CLIENT CERT PRESENTED (mutual TLS) ***"); X509_free(pc); }
            handle_client(ssl);
        } else {
            unsigned long e = ERR_get_error();
            char eb[256]; ERR_error_string_n(e, eb, sizeof(eb));
            std::fprintf(stderr, "[fake2] TLS handshake FAILED: %s\n", eb);
        }
        SSL_free(ssl);
        closesocket(c);
    }
    return 0;
}
