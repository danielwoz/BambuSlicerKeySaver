#pragma once
//
// cloud_tap: in-process capture of the genuine plugin's cloud HTTP plaintext.
//
// The plugin statically links OpenSSL and pins the cloud CA (slicer_base64.cer),
// so neither an LD_PRELOAD-style SSL_write symbol hook nor a proxy MITM (which
// would need the pinned verify overridden) is viable. But the plaintext HTTP
// request it builds (request line + X-BBL-* headers + Bearer token) and the
// plaintext response it decrypts (JSON, PEM cert/key) both live briefly in the
// plugin's PRIVATE heap while a request is in flight. This module runs a
// low-invasiveness background scanner (read-only VirtualQuery + memory reads --
// no breakpoints, no code patches) that dumps every distinct HTTP-plaintext
// block it sees to BBL_TAP_LOG.
//
// It captures exactly what a TLS MITM would see, read from the plugin's own
// buffers instead of the (encrypted) socket. Validate it against bambu_host's
// working get_user_print_info (api.bambulab.com/.../user/bind -> 200); it will
// also catch get_app_cert / create_task plaintext whenever the plugin makes
// those calls.

namespace bbl {

// Begin the background scanner. Writes to the file named by env BBL_TAP_LOG
// (append); if unset, logs to stderr. Idempotent.
void start_cloud_tap();

// Stop the scanner (runs one final pass first) and flush. Idempotent.
void stop_cloud_tap();

// Number of distinct HTTP-plaintext blocks dumped so far (diagnostic).
long long cloud_tap_hits();

}  // namespace bbl
