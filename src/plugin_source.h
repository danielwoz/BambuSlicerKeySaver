#pragma once
// Shared plugin-source facts used by BOTH the Linux daemon (src/daemon.cpp) and
// the Windows host (win/host/plugin_fetch.cpp). Keeping the version, the Bambu
// CDN manifest endpoint, and the manifest parse in one place means the two
// platforms download the SAME plugin the SAME way. Header-only; no behaviour
// change to either platform.
#include <cstddef>
#include <cstring>
#include <string>

namespace plugin_source {

// Plugin version the tool targets (cache subdir + version-locked extraction).
inline constexpr const char kVersion[] = "02.07.01.51";

// Bambu IoT slicer-resource manifest endpoint. The response is JSON listing
// resources (studio installer + plugin) whose "url" fields point at ZIPs. The
// X-BBL-OS-Type request header selects the per-OS build (linux / windows). The
// query carries a CHANNEL version (minor line + ".00"); the CDN resolves it to
// the current build in that line (e.g. cloud=02.06.01.00 -> plugin 02.06.01.50).
inline constexpr const char kManifestBase[] =
    "https://api.bambulab.com/v1/iot-service/api/slicer/resource?slicer/plugins/cloud=";

// The channel query value for a full version: "02.06.01.50" -> "02.06.01.00".
inline std::string channel_for(const std::string& version) {
    size_t last = version.find_last_of('.');
    return last == std::string::npos ? version : version.substr(0, last) + ".00";
}

// Full manifest URL to fetch the plugin build for `version`'s minor line.
inline std::string manifest_url_for(const std::string& version) {
    return std::string(kManifestBase) + channel_for(version);
}

// Default (current-version) manifest URL. Kept as a constant for callers (e.g.
// the Linux daemon) that just want the version this tool targets.
inline constexpr const char kManifestUrl[] =
    "https://api.bambulab.com/v1/iot-service/api/slicer/resource?slicer/plugins/cloud=02.07.01.00";

// Extract the PLUGIN ZIP url from the manifest JSON body. The manifest lists the
// studio installer first and the plugin second, so we select the "url" whose
// value points at "/plugins/" (falling back to the first url). Returns "" if none.
inline std::string parse_manifest_url(const std::string& body) {
    const char* key = "\"url\":\"";
    size_t pos = 0;
    std::string first;
    while ((pos = body.find(key, pos)) != std::string::npos) {
        size_t start = pos + std::strlen(key);
        size_t end = body.find('"', start);
        if (end == std::string::npos) break;
        std::string u = body.substr(start, end - start);
        if (first.empty()) first = u;
        if (u.find("/plugins/") != std::string::npos) return u;
        pos = end;
    }
    return first;
}

}  // namespace plugin_source
