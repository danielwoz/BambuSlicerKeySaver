// fake_broker2 (Linux port) — fake TLS+MQTT printer broker that drives the
// genuine plugin's enc_msg / secure-channel path so it fetches get_app_cert.
//
// Ported from the Windows harness (win/broker/fake_broker2.cpp). Behaviour:
//  * TLS server, self-signed RSA-2048 leaf, CN = device serial, SAN includes
//    the serial + 127.0.0.1 + localhost. SSL_VERIFY_NONE (BAMBU_MTLS=1 => peer).
//  * On SUBSCRIBE to device/<dev>/report: push a real-NP-capable push_status
//    report (BAMBU_FAKE_REPORT file, else a synthetic one carrying the fun flags)
//    — this is what flips the plugin into enc_msg mode.
//  * Reactive only: on a PUBLISH containing "app_cert"/"cert_request", reply with
//    a {"security":{"command":"app_cert_install", ... echoed sequence_id ...,
//    "printer_cert":"<PEM>"}} on device/<dev>/report. Echo the exact seq (a
//    mismatch => msgID 400 reject).
//
// Build: g++ -O2 -o fake_broker2 fake_broker2.cpp -lssl -lcrypto
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>

static std::string g_dev_id = "01S00A2B3C4D5E6";
static SSL_CTX*    g_ctx     = nullptr;
static std::string g_cert_pem;
static std::string g_key_pem;
static int         g_seq     = 5000;
static std::string g_real_report;

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

static void info_cb(const SSL* ssl, int where, int ret) {
    (void)ssl;
    if (where & SSL_CB_ALERT)
        std::fprintf(stderr, "[fake2] TLS ALERT %s: %s / %s\n",
                     (where & SSL_CB_READ) ? "recv" : "sent",
                     SSL_alert_type_string_long(ret), SSL_alert_desc_string_long(ret));
}
static int accept_any_client_cert(int, X509_STORE_CTX*) { return 1; }

static std::string g_cert_in;  // path to a CA-signed leaf cert (PEM), CN=<region>.mqtt.bambulab.com (cloud)
static std::string g_key_in;   // path to its private key (PEM)
static std::string g_dev_cert_in; // path to a self-signed device leaf (CN=<dev serial>) for the LOCAL channel
static std::string g_dev_key_in;
static SSL_CTX*    g_ctx_dev = nullptr;  // device-cert context (selected by SNI)

// SNI callback: cloud MQTT (SNI contains "mqtt.bambulab") keeps the CA-signed
// cloud leaf; the plugin's LOCAL device connection (SNI = serial / IP / none)
// gets the self-signed device-serial cert it expects, else it rejects the
// handshake ("unexpected eof").
static int sni_cb(SSL* ssl, int*, void*) {
    if (!g_ctx_dev) return SSL_TLSEXT_ERR_OK;
    const char* sni = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    bool cloud = sni && std::strstr(sni, "mqtt.bambulab");
    if (!cloud) SSL_set_SSL_CTX(ssl, g_ctx_dev);
    std::fprintf(stderr, "[fake2] SNI='%s' -> %s cert\n", sni ? sni : "(none)", cloud ? "cloud" : "device");
    return SSL_TLSEXT_ERR_OK;
}
static SSL_CTX* build_ctx_from(const std::string& crt, const std::string& key) {
    SSL_CTX* c = SSL_CTX_new(TLS_server_method());
    if (!c) return nullptr;
    if (SSL_CTX_use_certificate_chain_file(c, crt.c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(c, key.c_str(), SSL_FILETYPE_PEM) != 1) {
        std::fprintf(stderr, "[fake2] failed to load %s/%s\n", crt.c_str(), key.c_str());
        return nullptr;
    }
    SSL_CTX_set_verify(c, SSL_VERIFY_NONE, nullptr);
    return c;
}

// Build the SSL_CTX from a provided CA-signed leaf (so the plugin, which
// verifies the cloud-MQTT server cert against its trust store, accepts it).
static bool gen_ctx_from_files() {
    g_ctx = SSL_CTX_new(TLS_server_method());
    if (!g_ctx) return false;
    SSL_CTX_set_info_callback(g_ctx, info_cb);
    if (SSL_CTX_use_certificate_chain_file(g_ctx, g_cert_in.c_str()) != 1 ||
        SSL_CTX_use_PrivateKey_file(g_ctx, g_key_in.c_str(), SSL_FILETYPE_PEM) != 1) {
        logln("failed to load --cert-in/--key-in");
        return false;
    }
    { FILE* f=std::fopen(g_cert_in.c_str(),"rb"); if(f){ std::string s; char b[4096]; size_t n;
        while((n=std::fread(b,1,sizeof b,f))>0) s.append(b,n); std::fclose(f); g_cert_pem=s; } }
    const char* mtls = std::getenv("BAMBU_MTLS");
    SSL_CTX_set_verify(g_ctx, (mtls && mtls[0]=='1') ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                       (mtls && mtls[0]=='1') ? accept_any_client_cert : nullptr);
    std::fprintf(stderr, "[fake2] loaded CA-signed leaf from %s\n", g_cert_in.c_str());
    // Device-cert context for the LOCAL channel, selected by SNI.
    if (!g_dev_cert_in.empty() && !g_dev_key_in.empty()) {
        g_ctx_dev = build_ctx_from(g_dev_cert_in, g_dev_key_in);
        if (g_ctx_dev) {
            SSL_CTX_set_tlsext_servername_callback(g_ctx, sni_cb);
            std::fprintf(stderr, "[fake2] device-cert SNI context loaded from %s\n", g_dev_cert_in.c_str());
        }
    }
    return true;
}

static bool gen_ctx() {
    if (!g_cert_in.empty() && !g_key_in.empty()) return gen_ctx_from_files();
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

    { BIO* bio = BIO_new(BIO_s_mem()); PEM_write_bio_X509(bio, cert);
      char* d=nullptr; long n=BIO_get_mem_data(bio,&d); g_cert_pem.assign(d,(size_t)n); BIO_free(bio); }
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
static std::mutex g_write_mu;   // serialise SSL_write across reader + heartbeat threads
static bool ssl_write_all(SSL* ssl, const void* buf, size_t n) {
    std::lock_guard<std::mutex> lk(g_write_mu);
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

static std::string make_cert_report(const std::string& echo_seq) {
    std::string esc = json_escape(g_cert_pem);
    std::string seq = echo_seq;
    if (seq.empty()) { char seqbuf[16]; std::snprintf(seqbuf, sizeof seqbuf, "%d", g_seq++); seq = seqbuf; }
    const char* cmd = std::getenv("BAMBU_CERT_CMD");
    if (!cmd || !cmd[0]) cmd = "app_cert_install";
    return
        "{\"security\":{"
        "\"command\":\"" + std::string(cmd) + "\","
        "\"sequence_id\":\"" + seq + "\","
        "\"result\":\"success\","
        "\"reason\":\"success\","
        "\"err_code\":0,"
        "\"dev_id\":\"" + g_dev_id + "\","
        "\"printer_cert\":\"" + esc + "\""
        "}}";
}

static std::string extract_seq(const std::string& pl) {
    const std::string key = "\"sequence_id\":\"";
    size_t p = pl.find(key);
    if (p == std::string::npos) return {};
    p += key.size();
    size_t e = pl.find('"', p);
    if (e == std::string::npos) return {};
    return pl.substr(p, e - p);
}

// push_status carrying the NP-capable capability flags (real report preferred).
static std::string make_report() {
    if (!g_real_report.empty()) return g_real_report;
    return
        "{\"print\":{\"command\":\"push_status\",\"sequence_id\":\"0\","
        "\"result\":\"success\",\"fun\":\"4035FF1AFFF9CB7\",\"fun2\":\"1177\","
        "\"cfg\":\"401C5FC298\",\"aux\":\"2001004\",\"stat\":\"600248000\","
        "\"sec_link\":1,"
        "\"online\":{\"ahb\":true,\"rfid\":true,\"version\":7},"
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
                if (topic.find("/report") != std::string::npos && !report_pushed) {
                    std::string rep = make_report();
                    mqtt_publish(ssl, report_topic, rep);
                    report_pushed = true;
                    std::fprintf(stderr, "[fake2] pushed %s report (%zu bytes) to %s\n",
                                 g_real_report.empty() ? "SYNTH" : "REAL", rep.size(), report_topic.c_str());
                }
            }
        } else if (type == 3 && conn_sent) {   // PUBLISH from plugin
            if (body.size() < 2) continue;
            uint16_t tlen = ((uint16_t)body[0] << 8) | body[1];
            if ((size_t)(2 + tlen) > body.size()) continue;
            std::string topic(body.begin() + 2, body.begin() + 2 + tlen);
            size_t off = 2 + tlen;
            if ((hdr & 0x06) != 0) off += 2;
            std::string pl(body.begin() + (off <= body.size() ? off : body.size()), body.end());
            std::fprintf(stderr, "[fake2] PUBLISH topic='%s' payload[%zu]: %.*s\n",
                         topic.c_str(), pl.size(),
                         (int)(pl.size() > 200 ? 200 : pl.size()), pl.c_str());
            std::fflush(stderr);
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
            if ((hdr & 0x06) == 0x02 && body.size() >= (size_t)(2 + tlen + 2)) {
                uint16_t pid = ((uint16_t)body[2 + tlen] << 8) | body[3 + tlen];
                uint8_t puback[4] = {0x40, 0x02, (uint8_t)(pid >> 8), (uint8_t)(pid & 0xff)};
                ssl_write_all(ssl, puback, 4);
            }
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
            if (topic.find("/request") != std::string::npos && report_pushed) {
                mqtt_publish(ssl, report_topic, make_report());
            }
        } else if (type == 12) {               // PINGREQ
            uint8_t pingresp[2] = {0xd0, 0x00};
            ssl_write_all(ssl, pingresp, 2);
        } else if (type == 10) {               // UNSUBSCRIBE -> UNSUBACK (keep alive)
            uint16_t pid = body.size() >= 2 ? ((uint16_t)body[0] << 8) | body[1] : 0;
            uint8_t unsuback[4] = {0xb0, 0x02, (uint8_t)(pid >> 8), (uint8_t)(pid & 0xff)};
            ssl_write_all(ssl, unsuback, 4);
            std::fprintf(stderr, "[fake2] UNSUBSCRIBE pid=%u -> UNSUBACK (hdr=0x%02x body[%zu])\n",
                         pid, hdr, body.size());
        } else if (type == 14) {               // DISCONNECT
            std::fprintf(stderr, "[fake2] DISCONNECT hdr=0x%02x body=%zu\n", hdr, body.size());
            break;
        } else {
            char hx[64]={0}; for (size_t k=0;k<body.size()&&k<12;k++) std::snprintf(hx+k*3,4,"%02x ",body[k]);
            std::fprintf(stderr, "[fake2] packet type=%u hdr=0x%02x body[%zu]: %s\n", type, hdr, body.size(), hx);
        }
    }
}

int main(int argc, char** argv) {
    unsigned short port = 8883;
    const char* cert_out = nullptr; const char* key_out = nullptr;
    for (int i = 1; i + 1 < argc; ++i) {
        if (!std::strcmp(argv[i], "--dev-id")) g_dev_id = argv[i + 1];
        else if (!std::strcmp(argv[i], "--port")) port = (unsigned short)atoi(argv[i + 1]);
        else if (!std::strcmp(argv[i], "--cert-out")) cert_out = argv[i + 1];
        else if (!std::strcmp(argv[i], "--key-out"))  key_out  = argv[i + 1];
        else if (!std::strcmp(argv[i], "--cert-in"))  g_cert_in = argv[i + 1];
        else if (!std::strcmp(argv[i], "--key-in"))   g_key_in  = argv[i + 1];
        else if (!std::strcmp(argv[i], "--dev-cert-in")) g_dev_cert_in = argv[i + 1];
        else if (!std::strcmp(argv[i], "--dev-key-in"))  g_dev_key_in  = argv[i + 1];
    }
    g_real_report = load_file("BAMBU_FAKE_REPORT");
    if (!gen_ctx()) { logln("gen_ctx failed"); return 1; }
    if (cert_out) { FILE* f=std::fopen(cert_out,"wb"); if(f){std::fwrite(g_cert_pem.data(),1,g_cert_pem.size(),f);std::fclose(f);} }
    if (key_out)  { FILE* f=std::fopen(key_out,"wb");  if(f){std::fwrite(g_key_pem.data(),1,g_key_pem.size(),f);std::fclose(f);} }

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) { logln("socket failed"); return 1; }
    int on = 1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (bind(srv, (sockaddr*)&a, sizeof(a)) != 0) {
        std::fprintf(stderr, "[fake2] bind 127.0.0.1:%u failed\n", port); return 1;
    }
    if (listen(srv, 4) != 0) { logln("listen failed"); return 1; }
    std::fprintf(stderr, "[fake2] READY dev_id=%s port=%u\n", g_dev_id.c_str(), port);
    std::printf("READY\n"); std::fflush(stdout); std::fflush(stderr);

    // Multi-connection: the plugin opens BOTH a local channel (connect_printer)
    // and the cloud MQTT (start_subscribe), both redirected here — serve each in
    // its own thread so neither blocks the other.
    for (;;) {
        sockaddr_in peer{}; socklen_t plen = sizeof(peer);
        int c = accept(srv, (sockaddr*)&peer, &plen);
        if (c < 0) break;
        std::thread([c]() {
            // Peek the first bytes to see what the client actually sends
            // (0x16 0x03 = TLS ClientHello; "GET "/"POST" = HTTP; 0x10 = MQTT).
            unsigned char pk[16] = {0};
            ssize_t pn = recv(c, pk, sizeof pk, MSG_PEEK);
            char hx[64] = {0};
            for (ssize_t k = 0; k < pn && k < 12; k++) std::snprintf(hx + k*3, 4, "%02x ", pk[k]);
            std::fprintf(stderr, "[fake2] new conn: peek %zd bytes: %s | ascii='%.*s'\n",
                         pn, hx, (int)(pn > 0 ? pn : 0), (const char*)pk);
            std::fflush(stderr);
            SSL* ssl = SSL_new(g_ctx);
            SSL_set_fd(ssl, c);
            if (SSL_accept(ssl) == 1) {
                logln("TLS accepted (conn)");
                handle_client(ssl);
            } else {
                unsigned long e = ERR_get_error();
                char eb[256]; ERR_error_string_n(e, eb, sizeof(eb));
                std::fprintf(stderr, "[fake2] TLS handshake FAILED: %s\n", eb);
            }
            SSL_free(ssl);
            close(c);
        }).detach();
    }
    return 0;
}
