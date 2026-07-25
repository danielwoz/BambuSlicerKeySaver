#pragma once
// instr_cb -- a ProcessInstrumentationCallback that zeroes the debug-register
// fields out of CONTEXT buffers the plugin fills via a DIRECT `syscall`
// NtGetContextThread.
//
// The plugin's networking library reads its own thread context and, if it finds a
// nonzero hardware breakpoint in Dr0-7, aborts the cloud connect. verify_fake
// already zeroes the DR fields for callers of the ntdll EXPORTS (hk_ntgct), but
// the plugin also issues NtGetContextThread via its OWN inline
// `mov r10,rcx; mov eax,<ssn>; syscall` stub, which the export hooks do not see.
//
// A ProcessInstrumentationCallback runs on EVERY kernel->user return (including
// direct-syscall returns). When one fires from plugin/anonymous code after a
// context query, we locate the just-filled CONTEXT buffer (positively identified
// because its Dr7 == the value we programmed) and zero Dr0-3/Dr6/Dr7 before the
// plugin sees it. The real debug registers stay armed, so captures keep working.

#include <cstdint>
#include <cstdio>

namespace bbl {

// Install the process instrumentation callback. Call ONCE, early (before the
// plugin is loaded). Returns true on success. Idempotent.
//   scope_self=true  -> also treat OUR host exe as in-scope (for the self-test,
//                       whose direct-syscall read returns into the exe, not the
//                       plugin). Production installs pass false so host threads /
//                       the DR re-armer are never disturbed.
bool install_instrumentation_callback(bool scope_self = false);

// Remove the callback (best-effort; mainly for the self-test).
void remove_instrumentation_callback();

// Publish the currently-programmed Dr7 value so the callback can positively
// identify a leaked CONTEXT buffer (Dr7 match) irrespective of which register held
// the buffer pointer. aes_tap / verdict_flip call this whenever they (re)program
// the breakpoints. 0 disables the Dr7-match fast path (content scrub still runs
// for any buffer whose Dr0-3 are nonzero on a plugin-scoped return).
void instr_cb_set_armed_dr7(uint64_t dr7);
void instr_cb_set_armed_slots(uint64_t d0, uint64_t d1, uint64_t d2, uint64_t d3);

// Diagnostics.
long long instr_cb_fires();     // callback invocations that passed the scope gate
long long instr_cb_fires_raw(); // EVERY callback invocation (proves the mechanism fires at all)
long long instr_cb_scrubs();    // total CONTEXT buffers scrubbed
const char* instr_cb_last_path_name();          // where the last leaking buffer was found
void instr_cb_log_paths(FILE* out);             // per-path recovery counts

// Run the standalone self-test: set a real DR7 execute breakpoint on a dummy
// function on the current thread, read our own context via a hand-written DIRECT
// syscall stub (NOT the ntdll export), and confirm the instrumentation callback
// scrubbed Dr0-3/Dr7 to 0 while the breakpoint stays live (the BP still fires).
// Returns 0 on PASS, nonzero on FAIL. No plugin dependency.
int instrumentation_selftest();

}  // namespace bbl
