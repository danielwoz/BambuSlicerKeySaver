// appcert_driver — minimal faithful driver for the plugin's enc_msg /
// get_app_cert path (the bambu_host equivalent), bypassing the daemon's App /
// LanUplink device management. Drives the plugin handle directly:
//   init (create_agent + callbacks + connect_server) -> wait server_connected
//   -> start_subscribe("app") -> subscribe_device -> send_message loop.
// Run under the connect_redirect + fake_broker2 + trust bundle so the cloud
// MQTT lands on the local broker; get_app_cert HTTPS goes to real cloud.
//
// Build: g++ -std=c++17 -O2 appcert_driver.cpp bambu/BambuNetworkingPluginHandle.cpp
//            -Ibambu -ldl -lpthread -o appcert_driver
#include "BambuNetworkingPluginHandle.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <regex>
#include <fstream>

using namespace Slic3r::bambu;
static std::string env(const char* k, const char* d) {
    const char* v = std::getenv(k); return (v && *v) ? std::string(v) : std::string(d);
}

int main() {
    PluginHandleConfig cfg;
    cfg.plugin_path  = env("PLUGIN", "");
    cfg.config_dir   = env("CFG", "");
    cfg.country_code = env("COUNTRY", "Others");
    cfg.cert_dir     = env("CLOUD_CERT_DIR", "");
    cfg.cert_file    = env("CLOUD_CERT_FILE", "");
    std::string dev  = env("DEV", "");
    std::string msg  = env("MSG", "{\"print\":{\"command\":\"push_status\",\"sequence_id\":\"2001\"}}");
    int wait_s  = std::atoi(env("WAIT", "12").c_str());
    int rounds  = std::atoi(env("ROUNDS", "30").c_str());

    auto h = std::make_shared<BambuNetworkingPluginHandle>(cfg);
    std::fprintf(stderr, "[drv] init (plugin=%s dev=%s)...\n", cfg.plugin_path.c_str(), dev.c_str());
    if (!h->init()) { std::fprintf(stderr, "[drv] init FAILED\n"); return 1; }

    // change_user primes the cloud user session (some plugin builds gate the
    // privileged MQTT publishes / send path on this). user_info is the cloud
    // login blob; passed via BAMBU_USER_INFO (@file or inline JSON).
    if (const char* ui = std::getenv("BAMBU_USER_INFO"); ui && *ui) {
        std::string blob = ui;
        if (blob[0] == '@') {
            FILE* f = std::fopen(blob.c_str() + 1, "rb");
            if (f) { blob.clear(); char b[4096]; size_t n;
                while ((n = std::fread(b, 1, sizeof b, f)) > 0) blob.append(b, n);
                std::fclose(f); }
        }
        std::fprintf(stderr, "[drv] change_user(%zu bytes) rc=%d login=%d\n",
                     blob.size(), h->change_user(blob), (int)h->is_user_login());
    }

    // Hand the cloud session token to the agent the way Studio does
    // (GUI_App::handle_script_message -> change_user). The plugin auto-loads
    // BambuNetworkEngine.conf for the MQTT connect, but send_message_to_printer
    // requires change_user to have populated the in-session token, else rc=-2.
    // BAMBU_LOGIN_INFO points at the login_info JSON (data.token/refresh_token/
    // user.uid... — the HttpServer::do_request_login_info shape).
    if (const char* li = std::getenv("BAMBU_LOGIN_INFO"); li && li[0]) {
        FILE* f = std::fopen(li, "rb");
        if (f) {
            std::string info; char buf[8192]; size_t n;
            while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) info.append(buf, n);
            std::fclose(f);
            int rc = h->change_user(info);
            std::fprintf(stderr, "[drv] change_user(%zu bytes) rc=%d login=%d\n",
                         info.size(), rc, h->is_user_login() ? 1 : 0);
            // Re-connect after handing over the (refreshed) token; the first
            // connect_server in init() ran with the stale conf token.
            int crc = h->connect_server();
            std::fprintf(stderr, "[drv] re-connect_server rc=%d\n", crc);
        } else {
            std::fprintf(stderr, "[drv] BAMBU_LOGIN_INFO open fail: %s\n", li);
        }
    }

    // === Faithful bambu_host sequence (win/host/main.cpp) ===
    // Read printer IP and access code from BambuStudio.conf if not provided via env.
    std::string ip  = env("PRINTER_IP", "127.0.0.1");

    // Read access code from BambuStudio.conf "access_code" section.
    std::string acc = env("ACCESS_CODE", "");
    if (acc.empty()) {
        // Try to read from BambuStudio.conf
        const char* home = std::getenv("HOME");
        if (home && home[0]) {
            std::string conf_path = std::string(home) + "/.config/BambuStudio/BambuStudio.conf";
            FILE* f = std::fopen(conf_path.c_str(), "r");
            if (f) {
                fseek(f, 0, SEEK_END);
                long sz = ftell(f);
                rewind(f);
                std::string content(sz, '\0');
                fread(&content[0], 1, sz, f);
                fclose(f);

                // Find "access_code" section and extract device serial -> code mappings
                const char* key = "\"access_code\"";
                size_t pos = content.find(key);
                if (pos != std::string::npos) {
                    size_t start = content.find('{', pos);
                    if (start != std::string::npos) {
                        // Find the closing brace
                        int depth = 0;
                        bool in_str = false;
                        size_t end = std::string::npos;
                        for (size_t i = start; i < content.size(); ++i) {
                            char c = content[i];
                            if (in_str) {
                                if (c == '"' && content[i - 1] != '\\') in_str = false;
                            } else if (c == '"') {
                                in_str = true;
                            } else if (c == '{') {
                                ++depth;
                            } else if (c == '}') {
                                if (--depth == 0) { end = i; break; }
                            }
                        }
                        if (end != std::string::npos) {
                            std::string section = content.substr(start, end - start + 1);
                            // Extract first device serial -> access code pair
                            std::regex pair_re("\"([^\"]+)\"\\s*:\\s*\"([^\"]+)\"");
                            auto it = std::sregex_iterator(section.begin(), section.end(), pair_re);
                            if (it != std::sregex_iterator()) {
                                acc = (*it)[2].str();
                                std::fprintf(stderr, "[drv] read access code from BambuStudio.conf\n");
                            }
                        }
                    }
                }
            }
            if (acc.empty()) {
                std::fprintf(stderr, "[drv] error: no access code found in BambuStudio.conf\n");
                std::fprintf(stderr, "[drv] set ACCESS_CODE env var or use --access-code flag\n");
                return 1;
            }
        }
    }
    std::string user= env("PRINTER_USER", "bblp");

    h->register_local_message_receiver(dev, [](std::string,std::vector<uint8_t>,uint8_t){});
    h->register_receiver(dev, [](std::string,std::vector<uint8_t>,uint8_t){});
    // 1) connect_printer FIRST (bambu_host order). Skippable: on Linux the local
    //    channel TLS-fails (our CA cert != device cert), and telling the plugin
    //    there's a local endpoint makes it try to switch cloud->local and tear
    //    down the working cloud channel. SKIP_CONNECT_PRINTER=1 stays cloud-only.
    if (!(std::getenv("SKIP_CONNECT_PRINTER"))) {
        std::fprintf(stderr, "[drv] connect_printer(%s,%s) rc=%d\n", dev.c_str(), ip.c_str(),
                     h->connect_printer(dev, ip, user, acc, true));
        for (int i = 0; i < 60 && !h->is_local_connected(); i++)
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        std::fprintf(stderr, "[drv] is_local_connected=%d\n", (int)h->is_local_connected());
    } else {
        std::fprintf(stderr, "[drv] connect_printer SKIPPED (cloud-only)\n");
    }

    // 2) select machine, then bring up cloud MQTT: start_subscribe("app") is
    //    what actually connects the cloud session; without it send_message
    //    returns CONNECT_FAILED(-2). Wait for the REAL server-connected.
    std::fprintf(stderr, "[drv] set_user_selected_machine rc=%d\n", h->set_user_selected_machine(dev));
    std::fprintf(stderr, "[drv] start_subscribe(app) rc=%d\n", h->start_subscribe("app"));
    bool conn=false;
    for (int i = 0; i < 60; i++) { if (h->is_server_connected()) { conn=true; break; } std::this_thread::sleep_for(std::chrono::milliseconds(500)); }
    std::fprintf(stderr, "[drv] server_connected=%d\n", conn?1:0);

    // 3) cloud-subscribe the device (puts send_message on the signing path).
    std::fprintf(stderr, "[drv] subscribe_device rc=%d\n", h->subscribe_device(dev));
    h->install_device_cert(dev, false);

    // 4) probe loop: pushall (unprivileged, qos=0) each second until rc != -2
    //    (CONNECT_FAILED clears once the device cloud channel is live), then fire
    //    the privileged signed command (materialises the app key in memory).
    int settle = std::atoi(env("SETTLE", "30").c_str());
    bool open=false;
    for (int i = 0; i < settle; i++) {
        char probe[160];
        std::snprintf(probe, sizeof probe,
            "{\"pushing\":{\"command\":\"pushall\",\"sequence_id\":\"%d\"}}", 900000+i);
        int prc = h->send_message_to_printer(dev, probe, 0);
        std::fprintf(stderr, "[drv] settle %d: pushall rc=%d\n", i, prc);
        std::fflush(stderr);
        if (prc == 0) { open=true; std::fprintf(stderr, "[drv] *** publish path OPEN (rc=0) ***\n"); break; }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
    // 5) fire privileged signed commands (ams_filament_setting / print) to drive
    //    the enc_msg path -> get_app_cert fetch + app-key materialisation.
    // Signed command. Default: gcode_file referencing a NON-EXISTENT file — the
    // plugin builds the encrypted+signed enc_msg envelope (fetching get_app_cert
    // and materialising the app key) but NO real print starts (file doesn't
    // exist). rc=-2 is EXPECTED (plugin rejects print.* headless) — the key
    // still materialises during the build. Override with BAMBU_SIGN_CMD.
    const char* cmd = std::getenv("BAMBU_SIGN_CMD");  // "gcode" | "ams" (default ams, matches bambu_host)
    bool ams = !(cmd && !std::strcmp(cmd, "gcode"));
    for (int i = 0; i < rounds; i++) {
        // Mirror bambu_host trigger_fn EXACTLY: re-select machine + re-install the
        // device cert before EVERY send (this arms the enc_msg gate each time).
        h->set_user_selected_machine(dev);
        h->install_device_cert(dev, false);
        char sig[400];
        if (ams)
            std::snprintf(sig, sizeof sig,
                "{\"print\":{\"command\":\"ams_filament_setting\",\"sequence_id\":\"%d\","
                "\"ams_id\":0,\"slot_id\":0,\"tray_id\":0,\"tray_info_idx\":\"GFL96\","
                "\"tray_type\":\"PLA\",\"nozzle_temp_min\":190,\"nozzle_temp_max\":240}}", 800000+i);
        else
            std::snprintf(sig, sizeof sig,
                "{\"print\":{\"command\":\"gcode_file\",\"sequence_id\":\"%d\","
                "\"param\":\"Metadata/plate_1.gcode\","
                "\"url\":\"file:///mnt/sdcard/cache/net_nonexistent_%08x.gcode.3mf\","
                "\"md5\":\"00000000000000000000000000000000\",\"task_id\":\"0\"}}",
                800000+i, 0x1ea0db00u + (unsigned)i);
        int rc = h->send_message_to_printer(dev, sig, 1);
        if (i < 3 || (i % 10) == 0)
            std::fprintf(stderr, "[drv] signed send #%d rc=%d (expected -2; key materialises in build)\n", i, rc);
        std::fflush(stderr);
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }
    (void)wait_s;(void)msg;
    std::fprintf(stderr, "[drv] done (publish_open=%d); lingering\n", open?1:0);
    std::this_thread::sleep_for(std::chrono::seconds(6));
    return 0;
}
