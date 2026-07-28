// Minimal Win32 GUI front-end for the one-click key capture. A bare double-click
// of bambu_slicer_key_saver.exe lands here (see main.cpp): it hides the console
// log noise behind a small window with a spinner and, as each key is recovered,
// a "checkmark  Key type  -  <output path>" line. All the heavy lifting is the
// same run_auto_capture flow the console uses; this only renders its progress.
#include <windows.h>
#include <commctrl.h>
#include <string>
#include <thread>

#include "capture_ui.h"

// Defined in main.cpp (external linkage): runs the full 4-artifact capture with
// the given UI callbacks and returns when finished.
int run_capture_with_ui(const CaptureUI* ui);

namespace {

HWND        g_main = nullptr, g_list = nullptr, g_status = nullptr, g_bar = nullptr, g_close = nullptr;
HFONT       g_font = nullptr;
std::thread g_worker;

// Worker -> UI thread messages.
enum { WM_RESULT = WM_APP + 1, WM_STATUS, WM_DONE };

std::wstring widen(const char* s) {
    if (!s || !*s) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s, -1, nullptr, 0);
    if (n <= 1) return L"";
    std::wstring w((size_t)n - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s, -1, &w[0], n);
    return w;
}

// ---- CaptureUI callbacks (invoked on the capture worker thread) ----
void ui_result(void*, const char* key_type, bool ok, const char* path) {
    std::wstring line = ok ? L"✓  " : L"✗  ";   // check / ballot-X
    line += widen(key_type);
    if (ok && path && *path) { line += L"   →   "; line += widen(path); }   // arrow
    else if (!ok)            { line += L"   —   not extracted"; }           // em dash
    PostMessageW(g_main, WM_RESULT, 0, (LPARAM)new std::wstring(std::move(line)));
}
void ui_status(void*, const char* text) {
    PostMessageW(g_main, WM_STATUS, 0, (LPARAM)new std::wstring(widen(text)));
}
void ui_done(void*, int n) {
    PostMessageW(g_main, WM_DONE, (WPARAM)n, 0);
}
bool ui_confirm_no_printer(void*) {
    int r = MessageBoxW(g_main,
        L"No Bambu printer was found on your network.\n\n"
        L"The config, debug-log and app-certificate keys will still be extracted "
        L"normally. The slicer RSA key will be attempted WITHOUT a printer — a "
        L"slower, best-effort capture that can take several minutes and may not "
        L"succeed every run.\n\n"
        L"Continue?",
        L"No printer found", MB_YESNO | MB_ICONWARNING);
    return r == IDYES;
}

CaptureUI make_ui() {
    CaptureUI ui{};
    ui.on_result = ui_result;
    ui.on_status = ui_status;
    ui.on_done = ui_done;
    ui.confirm_no_printer = ui_confirm_no_printer;
    ui.ctx = nullptr;
    return ui;
}

void add_line(const std::wstring& s) {
    LRESULT i = SendMessageW(g_list, LB_ADDSTRING, 0, (LPARAM)s.c_str());
    // Keep long paths reachable via horizontal scroll.
    HDC dc = GetDC(g_list);
    HGDIOBJ old = SelectObject(dc, g_font);
    SIZE sz{}; GetTextExtentPoint32W(dc, s.c_str(), (int)s.size(), &sz);
    SelectObject(dc, old); ReleaseDC(g_list, dc);
    LRESULT ext = SendMessageW(g_list, LB_GETHORIZONTALEXTENT, 0, 0);
    if (sz.cx + 20 > ext) SendMessageW(g_list, LB_SETHORIZONTALEXTENT, sz.cx + 20, 0);
    if (i != LB_ERR) SendMessageW(g_list, LB_SETCURSEL, i, 0);
}

LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM wp, LPARAM lp) {
    switch (m) {
    case WM_CREATE: {
        HINSTANCE hi = ((LPCREATESTRUCT)lp)->hInstance;
        CreateWindowW(L"static", L"Recovering keys from the Bambu networking plugin…",
            WS_CHILD | WS_VISIBLE, 16, 12, 508, 20, h, nullptr, hi, nullptr);
        g_status = CreateWindowW(L"static", L"Starting…",
            WS_CHILD | WS_VISIBLE, 16, 36, 508, 20, h, nullptr, hi, nullptr);
        g_bar = CreateWindowExW(0, PROGRESS_CLASSW, nullptr,
            WS_CHILD | WS_VISIBLE | PBS_MARQUEE, 16, 62, 508, 16, h, nullptr, hi, nullptr);
        SendMessageW(g_bar, PBM_SETMARQUEE, TRUE, 30);
        g_list = CreateWindowExW(WS_EX_CLIENTEDGE, L"listbox", nullptr,
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL | LBS_NOINTEGRALHEIGHT | LBS_NOSEL,
            16, 90, 508, 232, h, (HMENU)101, hi, nullptr);
        g_close = CreateWindowW(L"button", L"Close",
            WS_CHILD | WS_VISIBLE | WS_DISABLED | BS_DEFPUSHBUTTON,
            432, 332, 92, 28, h, (HMENU)IDOK, hi, nullptr);
        for (HWND c : { g_status, g_list, g_close })
            SendMessageW(c, WM_SETFONT, (WPARAM)g_font, TRUE);
        SendMessageW(GetWindow(h, GW_CHILD), WM_SETFONT, (WPARAM)g_font, TRUE);
        return 0;
    }
    case WM_RESULT: { auto* s = (std::wstring*)lp; add_line(*s); delete s; return 0; }
    case WM_STATUS: { auto* s = (std::wstring*)lp; SetWindowTextW(g_status, s->c_str()); delete s; return 0; }
    case WM_DONE: {
        int n = (int)wp;
        SendMessageW(g_bar, PBM_SETMARQUEE, FALSE, 0);
        SetWindowLongPtrW(g_bar, GWL_STYLE, GetWindowLongPtrW(g_bar, GWL_STYLE) & ~PBS_MARQUEE);
        SendMessageW(g_bar, PBM_SETRANGE32, 0, 100); SendMessageW(g_bar, PBM_SETPOS, 100, 0);
        wchar_t buf[96];
        wsprintfW(buf, L"Done — %d of 4 keys extracted.", n);
        SetWindowTextW(g_status, buf);
        EnableWindow(g_close, TRUE);
        SetFocus(g_close);
        return 0;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK || (HWND)lp == g_close) { DestroyWindow(h); return 0; }
        break;
    case WM_CLOSE: DestroyWindow(h); return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(h, m, wp, lp);
}

}  // namespace

// Entry from main.cpp for a bare (no-argument) launch. Shows the window, runs the
// capture on a background thread, and pumps messages until the user closes it.
int run_gui() {
    // Hide the console ONLY if we own it (double-click allocates a fresh console);
    // when launched from an existing terminal, leave that terminal alone.
    DWORD pids[2]; DWORD np = GetConsoleProcessList(pids, 2);
    if (np == 1) { HWND con = GetConsoleWindow(); if (con) ShowWindow(con, SW_HIDE); }

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_PROGRESS_CLASS | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    NONCLIENTMETRICSW ncm{}; ncm.cbSize = sizeof(ncm);
    if (SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0))
        g_font = CreateFontIndirectW(&ncm.lfMessageFont);
    if (!g_font) g_font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

    HINSTANCE hi = GetModuleHandleW(nullptr);
    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hi;
    wc.lpszClassName = L"BblKeySaverWnd";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    RegisterClassW(&wc);

    RECT r{ 0, 0, 540, 372 };
    AdjustWindowRect(&r, WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX, FALSE);
    g_main = CreateWindowW(wc.lpszClassName, L"Bambu Slicer Key Saver",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, r.right - r.left, r.bottom - r.top,
        nullptr, nullptr, hi, nullptr);
    if (!g_main) return 1;
    ShowWindow(g_main, SW_SHOW);
    UpdateWindow(g_main);

    g_worker = std::thread([]() {
        CaptureUI ui = make_ui();
        run_capture_with_ui(&ui);
    });

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0)) { TranslateMessage(&msg); DispatchMessageW(&msg); }

    // The capture threads spawn child workers; let them finish/exit on their own
    // as the process tears down rather than blocking the window close.
    if (g_worker.joinable()) g_worker.detach();
    return 0;
}
