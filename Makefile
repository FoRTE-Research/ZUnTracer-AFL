#
# UnTracer-AFL - makefile
# -----------------------------
#
# Written by Stefan Nagy <snagy2@vt.edu>
#
# Based on AFL (american fuzzy lop) by Michal Zalewski <lcamtuf@google.com>
# 
# ------------Original copyright below------------
# 
# Copyright 2013, 2014, 2015, 2016, 2017 Google Inc. All rights reserved.
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
# 
#   http://www.apache.org/licenses/LICENSE-2.0
#

##################################################################

# UnTracer vars - edit DYN_ROOT accordingly

CC 			= gcc 
CXX 		= g++
CXXFLAGS 	= -g -Wall -O3 -std=c++11
LIBFLAGS 	= -fpic -shared
LDFLAGS 	= -I/usr/include

##################################################################

PROGNAME    = afl
VERSION     = $(shell grep '^\#define VERSION ' config.h | cut -d '"' -f2)

PREFIX     ?= /usr/local
BIN_PATH    = $(PREFIX)/bin
HELPER_PATH = $(PREFIX)/lib/afl
DOC_PATH    = $(PREFIX)/share/doc/afl
MISC_PATH   = $(PREFIX)/share/afl

# PROGS intentionally omit untracer-as, which gets installed elsewhere.

PROGS       = zuntracer-afl afl-showmap build-map
SH_PROGS    = afl-plot

CFLAGS     ?= -O3 -funroll-loops
CFLAGS     += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
	      -DAFL_PATH=\"$(HELPER_PATH)\" -DDOC_PATH=\"$(DOC_PATH)\" \
	      -DBIN_PATH=\"$(BIN_PATH)\"

ifneq "$(filter Linux GNU%,$(shell uname))" ""
  LDFLAGS  += -ldl
endif

ifeq "$(findstring clang, $(shell $(CC) --version 2>/dev/null))" ""
  TEST_CC   = zuntracer-gcc
else
  TEST_CC   = zuntracer-clang
endif

COMM_HDR    = alloc-inl.h config.h debug.h types.h

all: test_x86 $(PROGS) all_done

ifndef AFL_NO_X86

test_x86:
	@echo "[*] Checking for the ability to compile x86 code..."
	@echo 'main() { __asm__("xorb %al, %al"); }' | $(CC) -w -x c - -o .test || ( echo; echo "Oops, looks like your compiler can't generate x86 code."; echo; echo "Don't panic! You can use the LLVM or QEMU mode, but see docs/INSTALL first."; echo "(To ignore this error, set AFL_NO_X86=1 and try again.)"; echo; exit 1 )
	@rm -f .test
	@echo "[+] Everything seems to be working, ready to compile."

else

test_x86:
	@echo "[!] Note: skipping x86 compilation checks (AFL_NO_X86 set)."

endif

# UnTracer dependencies

zuntracer-afl: zuntracer-afl.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)

build-map: 
	chmod +X build-map.py

# AFL dependencies

afl-showmap: afl-showmap.c $(COMM_HDR) | test_x86
	$(CC) $(CFLAGS) $@.c -o $@ $(LDFLAGS)

all_done: 
	@echo "[+] All done! Be sure to review README - it's pretty short and useful."
	
.NOTPARALLEL: clean

clean:
	rm -f $(PROGS) *.o *~ a.out core core.[1-9][0-9]* *.stackdump test .test test-instr .test-instr0 .test-instr1 

install: all
	mkdir -p -m 755 $${DESTDIR}$(BIN_PATH) $${DESTDIR}$(HELPER_PATH) $${DESTDIR}$(DOC_PATH) $${DESTDIR}$(MISC_PATH)
	rm -f $${DESTDIR}$(BIN_PATH)/afl-plot.sh
	install -m 755 $(PROGS) $(SH_PROGS) $${DESTDIR}$(BIN_PATH)
	rm -f $${DESTDIR}$(BIN_PATH)/untracer-as
	if [ -f afl-qemu-trace ]; then install -m 755 afl-qemu-trace $${DESTDIR}$(BIN_PATH); fi
ifndef AFL_TRACE_PC
	if [ -f untracer-clang-fast -a -f afl-llvm-pass.so -a -f afl-llvm-rt.o ]; then set -e; install -m 755 untracer-clang-fast $${DESTDIR}$(BIN_PATH); ln -sf untracer-clang-fast $${DESTDIR}$(BIN_PATH)/untracer-clang-fast++; install -m 755 afl-llvm-pass.so afl-llvm-rt.o $${DESTDIR}$(HELPER_PATH); fi
else
	if [ -f untracer-clang-fast -a -f afl-llvm-rt.o ]; then set -e; install -m 755 untracer-clang-fast $${DESTDIR}$(BIN_PATH); ln -sf untracer-clang-fast $${DESTDIR}$(BIN_PATH)/untracer-clang-fast++; install -m 755 afl-llvm-rt.o $${DESTDIR}$(HELPER_PATH); fi
endif
	if [ -f afl-llvm-rt-32.o ]; then set -e; install -m 755 afl-llvm-rt-32.o $${DESTDIR}$(HELPER_PATH); fi
	if [ -f afl-llvm-rt-64.o ]; then set -e; install -m 755 afl-llvm-rt-64.o $${DESTDIR}$(HELPER_PATH); fi
	set -e; for i in untracer-g++ untracer-clang untracer-clang++; do ln -sf untracer-gcc $${DESTDIR}$(BIN_PATH)/$$i; done
	install -m 755 untracer-as $${DESTDIR}$(HELPER_PATH)
	ln -sf untracer-as $${DESTDIR}$(HELPER_PATH)/as
	install -m 644 docs/README docs/ChangeLog docs/*.txt $${DESTDIR}$(DOC_PATH)
	cp -r testcases/ $${DESTDIR}$(MISC_PATH)
	cp -r dictionaries/ $${DESTDIR}$(MISC_PATH)

publish: clean
	test "`basename $$PWD`" = "afl" || exit 1
	test -f ~/www/afl/releases/$(PROGNAME)-$(VERSION).tgz; if [ "$$?" = "0" ]; then echo; echo "Change program version in config.h, mmkay?"; echo; exit 1; fi
	cd ..; rm -rf $(PROGNAME)-$(VERSION); cp -pr $(PROGNAME) $(PROGNAME)-$(VERSION); \
	  tar -cvz -f ~/www/afl/releases/$(PROGNAME)-$(VERSION).tgz $(PROGNAME)-$(VERSION)
	chmod 644 ~/www/afl/releases/$(PROGNAME)-$(VERSION).tgz
	( cd ~/www/afl/releases/; ln -s -f $(PROGNAME)-$(VERSION).tgz $(PROGNAME)-latest.tgz )
	cat docs/README >~/www/afl/README.txt
	cat docs/status_screen.txt >~/www/afl/status_screen.txt
	cat docs/historical_notes.txt >~/www/afl/historical_notes.txt
	cat docs/technical_details.txt >~/www/afl/technical_details.txt
	cat docs/ChangeLog >~/www/afl/ChangeLog.txt
	cat docs/QuickStartGuide.txt >~/www/afl/QuickStartGuide.txt
	echo -n "$(VERSION)" >~/www/afl/version.txt
