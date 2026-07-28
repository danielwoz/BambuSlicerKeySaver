Bambu Slicer Key Saver (Windows)
================================

Recovers, from the Bambu networking plugin already installed with Bambu Studio,
the keys that identify your slicer to Bambu's services:

  * Slicer RSA key          (slicer_key.txt / slicer_key.pem)
  * Config AES key           (network_engine.key / config_key.txt)
  * Debug-log AES key        (debug_log.key / log_key.txt)
  * Cloud app certificate    (appcert_out\app_cert.pem)


HOW TO USE
----------

1. Install and sign in to Bambu Studio at least once (the tool reads the
   plugin and your saved login; nothing is sent anywhere).

2. CLOSE Bambu Studio before running this — it uses its own copy of the
   plugin and will interfere with the capture.

3. For the slicer RSA key, have a Bambu printer powered on and reachable on
   the same network (LAN). The other three keys do not need a printer.

4. Double-click  bambu_slicer_key_saver.exe

   A small window opens with a progress spinner. As each key is recovered a
   line appears:

       [check]  Config AES key (network_engine.key)  ->  <path>

   When it finishes it shows how many of the four keys were extracted. The
   files are written next to the program (in an "autocap\out" folder).

If no printer is found, the tool warns you and asks whether to continue with
just the other three keys.


COMMAND LINE (optional)
-----------------------

Running with any argument uses the console instead of the window:

    bambu_slicer_key_saver.exe --auto-capture   all four keys (needs a printer)
    bambu_slicer_key_saver.exe --auto           slicer RSA key only, no printer
    bambu_slicer_key_saver.exe --find-config-key config AES key only
    bambu_slicer_key_saver.exe --find-log-key    debug-log AES key only


NOTES
-----

* Keep every file in this folder together — the program needs the OpenSSL and
  Visual C++ runtime DLLs shipped alongside it.
* Windows Defender or other antivirus may flag the tool because it reads
  another process's memory; allow it if prompted.
* These are YOUR OWN keys from YOUR installation. Keep the output files
  private — treat them like a password.
