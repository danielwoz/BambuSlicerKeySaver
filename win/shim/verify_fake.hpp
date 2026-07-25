#pragma once

// Verification shim for the Windows port of BambuSlicerKeySaver.
//
// bambu_networking.dll runs Authenticode / identity checks on the host process
// (the .exe and the "BambuStudio.dll" it expects to be loaded by) before it
// will operate. This shim hooks those Windows APIs and returns success for the
// plugin's own trust queries, so the plugin loads and operates without a
// separate signed host install.
//
// install_verify_fake() must be called BEFORE LoadLibrary of the plugin so the
// hooks are live when the plugin initializes. It is idempotent.
//
// Every intercepted call is logged (to stderr and, if BBL_SHIM_LOG is set, to
// that file) so a run records which checks the plugin performs.

namespace bbl {

void install_verify_fake();

}  // namespace bbl
