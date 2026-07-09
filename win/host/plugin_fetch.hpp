#pragma once
#include <string>

// Windows analogue of the Linux daemon's download_plugin_if_needed(): fetch the
// proprietary bambu_networking.dll from the Bambu CDN (same manifest endpoint and
// version as Linux, see src/plugin_source.h) and cache it under %LOCALAPPDATA%.
// Returns the cached DLL path, or "" on failure.

namespace bbl {
// version: full plugin version, e.g. "02.06.01.50"; empty -> the tool's default
// (plugin_source::kVersion). The CDN resolves the version's minor-line channel.
std::string download_plugin_win(const std::string& version = "");

// Path to an already-downloaded plugin for `version` (empty -> tool default),
// or "" if not cached. Never downloads; use download_plugin_win() to fetch.
std::string cached_plugin_path(const std::string& version = "");
}
