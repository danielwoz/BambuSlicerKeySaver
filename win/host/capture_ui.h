#pragma once
// UI hooks for run_auto_capture so the same capture flow can drive either the
// console (plain stderr) or the GUI (win/host/gui.cpp). Every callback is
// optional -- a null CaptureUI* (or null members) preserves the console
// behaviour. Callbacks fire on the capture worker thread; the GUI marshals them
// to its UI thread.
struct CaptureUI {
    // One artifact stage finished. key_type e.g. "Slicer RSA key"; ok = success;
    // path = the output file/dir (empty on failure).
    void (*on_result)(void* ctx, const char* key_type, bool ok, const char* path);
    // Short status line, e.g. "Recovering config key...".
    void (*on_status)(void* ctx, const char* text);
    // No Bambu printer was found on the LAN (the slicer RSA key needs one; the
    // other keys do not). Return true to continue with the remaining keys, false
    // to abort. Null => continue by default (console behaviour).
    bool (*confirm_no_printer)(void* ctx);
    // Whole run finished; artifacts_ok = how many of the four succeeded.
    void (*on_done)(void* ctx, int artifacts_ok);
    void* ctx;
};
