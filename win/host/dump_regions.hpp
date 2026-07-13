#pragma once
// dump_plugin_regions — snapshot the loaded bambu_networking.dll's committed,
// readable memory (image sections + anonymous private regions) to files under
// out_dir, with a MANIFEST.txt. Used to disassemble the get_app_cert crypto
// offline. Uses VirtualQuery only, with no debugger or hardware breakpoint.
// Returns 0 on success.

namespace bbl {
int dump_plugin_regions(const char* out_dir);
}
