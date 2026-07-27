#pragma once
// Shared, cross-platform BambuStudio config helpers used by BOTH the Linux tool
// (src/) and the Windows host (win/). Keeping this in one place stops the two
// ports' copies from drifting (e.g. the device-id auto-detect, which had
// diverged between src/main.cpp and win/host/lan_discover.cpp). Header-only and
// std-only so either build can include it with no extra sources or link deps.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace bbl_config {

// Path separator for the current OS.
inline const char* sep() {
#if defined(_WIN32)
    return "\\";
#else
    return "/";
#endif
}

// The OS-specific BambuStudio user config directory, where the saved key is
// written by default and where BambuStudio.conf lives.
inline std::string config_dir() {
#if defined(_WIN32)
    if (const char* appdata = std::getenv("APPDATA"); appdata && appdata[0])
        return std::string(appdata) + "\\BambuStudio";
    return "BambuStudio";
#elif defined(__APPLE__)
    if (const char* home = std::getenv("HOME"); home && home[0])
        return std::string(home) + "/Library/Application Support/BambuStudio";
    return "BambuStudio";
#else
    // Linux / other Unix: honour XDG_CONFIG_HOME, else ~/.config.
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME"); xdg && xdg[0])
        return std::string(xdg) + "/BambuStudio";
    if (const char* home = std::getenv("HOME"); home && home[0])
        return std::string(home) + "/.config/BambuStudio";
    return "BambuStudio";
#endif
}

// Full path to BambuStudio.conf.
inline std::string conf_path() {
    return config_dir() + sep() + "BambuStudio.conf";
}

// Value of a top-level "field":"value" string in BambuStudio.conf, or "" if the
// file or field is absent. Plain string walk -- no JSON library dependency.
inline std::string conf_string_field(const char* field) {
    FILE* f = std::fopen(conf_path().c_str(), "rb");
    if (!f) return "";
    std::string raw;
    char b[8192];
    size_t n;
    while ((n = std::fread(b, 1, sizeof b, f)) > 0) raw.append(b, n);
    std::fclose(f);
    const std::string key = std::string("\"") + field + "\"";
    size_t p = raw.find(key);
    if (p == std::string::npos) return "";
    p = raw.find(':', p + key.size());
    if (p == std::string::npos) return "";
    p = raw.find('"', p);
    if (p == std::string::npos) return "";
    size_t e = raw.find('"', p + 1);
    if (e == std::string::npos) return "";
    return raw.substr(p + 1, e - p - 1);
}

// The device id BambuStudio last had selected ("user_last_selected_machine"),
// used as the --dev-id default so a logged-in install needs no device argument.
// Empty if not found.
inline std::string detect_last_machine() {
    return conf_string_field("user_last_selected_machine");
}

// Load the 16-byte debug-log AES key from BAMBU_LOG_ENC_KEY (a path to a 16-byte
// key file) or <config_dir>/log_enc.key. Returns true and fills key[16] on
// success. The key is not hardcoded; recover it with the tool's log-key mode and
// place it at one of those locations.
inline bool load_log_key(unsigned char key[16]) {
    if (const char* env_path = std::getenv("BAMBU_LOG_ENC_KEY"); env_path && env_path[0]) {
        if (FILE* f = std::fopen(env_path, "rb")) {
            size_t n = std::fread(key, 1, 16, f);
            std::fclose(f);
            if (n == 16) return true;
        }
    }
    std::string path = config_dir() + sep() + "log_enc.key";
    if (FILE* f = std::fopen(path.c_str(), "rb")) {
        size_t n = std::fread(key, 1, 16, f);
        std::fclose(f);
        if (n == 16) return true;
    }
    return false;
}

}  // namespace bbl_config
