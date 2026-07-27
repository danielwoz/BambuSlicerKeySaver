#pragma once
// LAN printer discovery + BambuStudio access-code lookup for the auto-capture mode.
#include <string>
#include <vector>
#include <map>

namespace bbl {

struct LanPrinter {
    std::string serial;   // device serial (SSDP USN)
    std::string ip;       // LAN IP (SSDP Location)
    std::string name;     // friendly name (DevName.bambu.com), falls back to serial
};

// Listen for Bambu SSDP NOTIFY on 239.255.255.250:2021 for up to `timeout_s`
// seconds and return the real LAN printers seen (virtual "FFFF..." devices are
// excluded). This is how BambuStudio discovers printers on the LAN.
std::vector<LanPrinter> discover_lan_printers(int timeout_s);

// Read %APPDATA%/BambuStudio/BambuStudio.conf and return the serial -> access-code
// map from its "access_code" object. Empty if the file or section is absent.
std::map<std::string, std::string> read_studio_access_codes();

// The last-selected device id from BambuStudio.conf ("user_last_selected_machine"),
// used as the --dev-id default. Empty if not found.
std::string read_studio_last_machine();

}  // namespace bbl
