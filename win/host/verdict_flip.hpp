#pragma once
//
// Locate the plugin's cached verification result and adjust it via a hardware
// (Dr0-Dr3) execute breakpoint so the enc_msg sign path proceeds.
//
// Uses memory reads + debug registers only -- no code byte-patching.
//   1. Snapshot the plugin's decrypted memory; find VAs of the verification
//      log strings ("enc_msg: unsigned studio", "not studio sequence_int = {}",
//      "verify ok", "verify failed...").
//   2. Scan the plugin's executable regions for RIP-relative LEA (48 8d 0d/15/05
//      <disp32>) whose target == a verification-string VA -- the log call sites.
//   3. Backward-scan from the unsigned-studio LEA to the nearest guarding Jcc:
//      that Jcc is the decision.
//   4. Arm a DR execute BP at the Jcc; in the VEH steer the branch to the
//      verified direction so the plugin proceeds to the sign path.

#include <cstdint>
#include <vector>
#include <string>

namespace bbl {

struct VerdictSite {
    uint64_t str_va      = 0;
    std::string str_text;
    uint64_t lea_va      = 0;
    uint64_t lea_end     = 0;
    uint64_t jcc_va      = 0;
    uint8_t  jcc_opcode  = 0;
    bool     jcc_near    = false;
    uint64_t jcc_end     = 0;
    uint64_t jcc_target  = 0;
    uint8_t  cmp_kind    = 0;
    uint64_t cmp_va      = 0;
};

std::vector<VerdictSite> find_verdict_sites();

bool arm_verdict_flip(const std::vector<VerdictSite>& sites);
void disarm_verdict_flip();
long long verdict_flip_hits();

// Runtime trace: arm a DR execute BP on the unsigned_studio message-construction
// LEA; on the first hit capture full register state, the stack return chain, and
// a backward-aligned disassembly, to identify the decision instruction at
// runtime. Returns the LEA VA armed (0 if none). Trace output goes to stderr.
uint64_t trace_unsigned_studio(const std::vector<VerdictSite>& sites);
bool trace_captured();

// Disassemble a window around `va` (backward-aligned + forward), annotating Jcc /
// cmp/test, so the branch feeding a push-site can be read off.
void disasm_va(uint64_t va, int back, int fwd);

// Return the loaded base of bambu_networking.dll (0 if not loaded).
uint64_t plugin_base();

// Arm a DR execute BP at `branch_va` (a Jcc). On hit, steer RIP to `verified_va`
// (control-flow redirect; no code write). Stays armed until disarm_verdict_flip().
// This is the explicit-target form used once the branch + verified edge are known
// from the stack-walk + disassembly.
bool arm_flip_at(uint64_t branch_va, uint64_t verified_va);

// A verification call-site frame return-address points right at a
//   test al,al ; jnz <verified>   (verified when the bool != 0)
// pattern. Decode it: on success fill *jnz_va (the conditional branch) and
// *jnz_target (the verified edge). Returns true if the pattern matched.
bool find_al_test_jnz(uint64_t frame_va, uint64_t* jnz_va, uint64_t* jnz_target);

// Arm the DR breakpoint using the frames captured on the first unsigned_studio
// push (frame return-addresses). For each frame matching test-al;jnz it arms a DR
// BP (up to 4) steering the branch to the verified edge. Returns the number armed.
int arm_flip_from_frames(const std::vector<unsigned long long>& frames);

// Coordination for external thread-suspend consumers (e.g. blind_extract's
// freeze-snapshot). While paused, the re-armer will NOT SuspendThread other
// threads, avoiding a double-suspend deadlock. Bracket any freeze with these.
void flip_pause_rearm();
void flip_resume_rearm();

// Re-program the DR breakpoints on all threads ONCE, synchronously. Use this
// from inside an external freeze consumer (which already owns the moment all
// threads are suspend/resume-coordinated) so there is exactly ONE thread doing
// SuspendThread. Stop the background re-armer (disarm keeps slots) before relying
// on this. No-op if the breakpoint is not armed.
void flip_rearm_now();

// Stop just the background re-armer thread (keeps the DR slots + VEH). Pair with
// flip_rearm_now() driven externally.
void flip_stop_background_rearm();

// ---------------------------------------------------------------------------
// READ-AT-BREAKPOINT capture gate.
//
// The flip fires on the SIGNING thread at the exact `test al,al; jnz` that
// guards the sign path -- at that instant the RSA key struct (p/q) is live and
// resident in the heap and the thread is PAUSED inside our VEH. This gate lets an
// external capturer read the key deterministically at that moment: the VEH
// signals a held capture window, then SPINS the sign thread in-place (still
// inside the VEH, no RIP move) for up to `hold_ms` while the capturer runs a
// fast plain heap sweep, so p/q cannot be freed/overwritten mid-scan.
//
// Usage (capturer thread):
//   flip_enable_capture_gate(hold_ms);              // arm the gate
//   while (!done) {
//       if (flip_wait_capture_window(timeout_ms)) { // a flip is holding NOW
//           done = blind_scan_once(...);            // p/q guaranteed resident
//           flip_release_capture_window();          // let the sign thread go
//       }
//   }
//   flip_disable_capture_gate();
//
// The hold is bounded (hold_ms) and self-releases if the capturer is slow, so a
// slow/blocked scan can never wedge the plugin. Multiple flips may fire; only
// one capture window is held at a time (the others fall through un-held).
void flip_enable_capture_gate(int hold_ms);
void flip_disable_capture_gate();

// Block up to `timeout_ms` for the VEH to announce a held capture window (a sign
// thread is paused at the branch). Returns true if a window is open (the sign
// thread is being held) -- the caller MUST call flip_release_capture_window()
// promptly afterwards. Returns false on timeout (no breakpoint fired).
bool flip_wait_capture_window(int timeout_ms);

// Release the sign thread held by the current capture window (idempotent).
void flip_release_capture_window();

// Total number of capture windows the VEH has opened (diagnostic).
long long flip_capture_windows();

}  // namespace bbl
