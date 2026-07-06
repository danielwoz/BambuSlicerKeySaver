# Build the bambu_slicer_key_saver self-contained binary.
#
# Prerequisites:
#   apt install build-essential cmake ninja-build xxd curl unzip \
#               libssl-dev libcurl4-openssl-dev zlib1g-dev
#
# All embed headers are built from source automatically.  Build everything with:
#   make

CXX      ?= g++
CC       ?= gcc
CXXFLAGS ?= -std=c++17 -O2 -DUSE_SECCOMP_UNOTIFY -Wall -Wextra
# STATIC=1 statically links OpenSSL/zlib/libstdc++/libgcc for a portable release
# binary, while keeping glibc dynamic — the bootstrap LD_PRELOADs the watchdog
# shim into a self-re-exec and the daemon dlopen()s the plugin, both of which
# need the dynamic glibc loader, so a fully -static binary would not work.
ifdef STATIC
LDFLAGS  ?= -static-libstdc++ -static-libgcc \
            -Wl,-Bstatic -lssl -lcrypto -lz -Wl,-Bdynamic -lpthread -ldl
else
LDFLAGS  ?= -lpthread -ldl -lssl -lcrypto -lz
endif

SRCS = main.cpp \
       version.cpp \
       bigint.cpp \
       envelope.cpp \
       capture.cpp \
       fake_broker.cpp \
       reconstruct.cpp \
       output.cpp \
       daemon.cpp \
       vendored/BigIntModExp.cpp \
       vendored/mqtt_mini_broker.cpp

EMBED_HEADERS = daemon_embed.h connect_redirect_embed.h watchdog_defeat_embed.h \
                watchdog_defeat_v2_embed.h allow_ptrace_embed.h \
                rdtsc_fake_embed.h

HEADERS = logging.h \
          version.h \
          bigint.h \
          envelope.h \
          capture.h \
          reconstruct.h \
          output.h \
          fake_broker.h \
          daemon.h

.PHONY: all clean

all: bambu_slicer_key_saver bambu_conf_decrypt

bambu_slicer_key_saver: $(SRCS) $(EMBED_HEADERS) $(HEADERS)
	$(CXX) $(CXXFLAGS) -o $@ $(SRCS) $(LDFLAGS)

# Standalone offline decoder for BambuNetworkEngine.conf (no plugin needed).
bambu_conf_decrypt: bambu_conf_decrypt.cpp
	$(CXX) $(CXXFLAGS) -o $@ $< -lcrypto

# connect_redirect.so is built from source in this repo.
build/connect_redirect.so: connect_redirect.c | build
	$(CC) -shared -fPIC -O2 -nostartfiles -o $@ $< -ldl -lssl

connect_redirect_embed.h: build/connect_redirect.so
	xxd -i $< \
	  | sed 's/^unsigned char build_connect_redirect_so/static unsigned char connect_redirect_embed_so/' \
	  | sed 's/^unsigned int  *build_connect_redirect_so_len/static unsigned int  connect_redirect_embed_so_len/' \
	  > $@

build/daemon/bambu-daemon: daemon/CMakeLists.txt | build
	cmake -S daemon -B build/daemon -DCMAKE_BUILD_TYPE=Release \
	      -DCMAKE_EXE_LINKER_FLAGS="-Wl,--strip-all" -Wno-dev -G Ninja -DCMAKE_MAKE_PROGRAM=ninja
	cmake --build build/daemon --parallel

daemon_embed.h: build/daemon/bambu-daemon
	xxd -i $< \
	  | sed 's/^unsigned char build_daemon_bambu_daemon/static const unsigned char daemon_embed_bin/' \
	  | sed 's/^unsigned int  *build_daemon_bambu_daemon_len/static const size_t daemon_embed_bin_len/' \
	  > $@

build/watchdog_defeat.so: shims/watchdog_defeat.c | build
	$(CC) -shared -fPIC -O2 -o $@ $< -ldl -pthread

watchdog_defeat_embed.h: build/watchdog_defeat.so
	xxd -i $< \
	  | sed 's/^unsigned char build_watchdog_defeat_so/static unsigned char watchdog_defeat_embed_so/' \
	  | sed 's/^unsigned int  *build_watchdog_defeat_so_len/static unsigned int  watchdog_defeat_embed_so_len/' \
	  > $@

# watchdog_defeat_v2: preloaded into the plugin (daemon) process. Required for
# newer plugin builds (e.g. 02.08) whose anti-debug otherwise std::terminate()s
# the process mid-capture. MUST be built with gcc — clang's codegen for its
# SIGSEGV/seccomp/inline-asm paths produces a functionally broken shim.
build/watchdog_defeat_v2.so: shims/watchdog_defeat_v2.c | build
	gcc -shared -fPIC -O2 -o $@ $< -ldl -pthread

build/rdtsc_fake.so: shims/rdtsc_fake.c | build
	gcc -shared -fPIC -O2 -o $@ $< -ldl

rdtsc_fake_embed.h: build/rdtsc_fake.so
	xxd -i $< \
	  | sed 's/^unsigned char build_rdtsc_fake_so/static unsigned char rdtsc_fake_embed_so/' \
	  | sed 's/^unsigned int  *build_rdtsc_fake_so_len/static unsigned int  rdtsc_fake_embed_so_len/' \
	  > $@

build/allow_ptrace.so: shims/allow_ptrace.c | build
	gcc -shared -fPIC -O2 -o $@ $< -ldl

allow_ptrace_embed.h: build/allow_ptrace.so
	xxd -i $< \
	  | sed 's/^unsigned char build_allow_ptrace_so/static unsigned char allow_ptrace_embed_so/' \
	  | sed 's/^unsigned int  *build_allow_ptrace_so_len/static unsigned int  allow_ptrace_embed_so_len/' \
	  > $@

watchdog_defeat_v2_embed.h: build/watchdog_defeat_v2.so
	xxd -i $< \
	  | sed 's/^unsigned char build_watchdog_defeat_v2_so/static unsigned char watchdog_defeat_v2_embed_so/' \
	  | sed 's/^unsigned int  *build_watchdog_defeat_v2_so_len/static unsigned int  watchdog_defeat_v2_embed_so_len/' \
	  > $@

build:
	mkdir -p build

clean:
	rm -f bambu_slicer_key_saver
	rm -rf build
	rm -f connect_redirect_embed.h daemon_embed.h watchdog_defeat_embed.h
