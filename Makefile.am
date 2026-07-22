# includes append to these:
SUFFIXES =
TESTS =
CLEANFILES =
DISTCLEANFILES =
bin_PROGRAMS =
noinst_HEADERS =
lib_LTLIBRARIES =
man_MANS =
noinst_LTLIBRARIES =
noinst_PROGRAMS =
include_HEADERS =
nobase_include_HEADERS =
check_PROGRAMS =
EXTRA_HEADERS =
BUILT_SOURCES =
EXTRA_DIST =
noinst_SCRIPTS =
check_SCRIPTS =
dist_noinst_SCRIPTS =
dist_doc_DATA =


#includes additional rules from aminclude.am
@INC_AMINCLUDE@
DISTCLEANFILES+= aminclude.am

# make sure we pass the correct flags to distcheck
# SWTPM_PORT can be set via --with-swtpm-port during configure
# Use @SWTPM_PORT@ substitution from configure.ac
# Explicitly disable fwtpm during distcheck — fwtpm_server requires
# optional wolfSSL features (WOLFSSL_KEY_GEN, WC_RSA_NO_PADDING) that
# distcheck runners can't guarantee. Restores pre-auto-enable behavior.
AM_DISTCHECK_CONFIGURE_FLAGS = --enable-swtpm --disable-fwtpm @DISTCHECK_SWTPM_PORT_FLAG@

exampledir = $(docdir)/example
dist_example_DATA=

ACLOCAL_AMFLAGS= -I m4


include src/include.am
include wolftpm/include.am
include examples/include.am
include scripts/include.am
include IDE/include.am
include certs/include.am
include tests/include.am
include docs/include.am
include wrapper/include.am
include hal/include.am
include src/spdm/include.am
include src/fwtpm/include.am
include cmake/include.am
include zephyr/include.am

EXTRA_DIST+= .cyignore
EXTRA_DIST+= README.md
EXTRA_DIST+= ChangeLog.md
EXTRA_DIST+= LICENSE
EXTRA_DIST+= COPYING
EXTRA_DIST+= autogen.sh
EXTRA_DIST+= CMakeLists.txt

TEST_EXTENSIONS=.test
TESTS += $(check_PROGRAMS)

check_SCRIPTS+= $(dist_noinst_SCRIPTS)
TESTS += $(check_SCRIPTS)

test: check

DISTCLEANFILES+= wolftpm-config


maintainer-clean-local:
	-rm Makefile.in
	-rm aclocal.m4
	-rm build-aux/compile
	-rm build-aux/config.guess
	-rm build-aux/config.sub
	-rm build-aux/depcomp
	-rm build-aux/install-sh
	-rm build-aux/ltmain.sh
	-rm build-aux/missing
	-rm wolftpm-config
	-rmdir build-aux
	-rm configure
	-rm config.log
	-rm config.status
	-rm config.in
	-rm m4/libtool.m4
	-rm m4/ltoptions.m4
	-rm m4/ltsugar.m4
	-rm m4/ltversion.m4
	-rm m4/lt~obsolete.m4
	find . -type f -name '*~' -exec rm -f '{}' \;
	-rm -f @PACKAGE@-*.tar.gz
	-rm -f @PACKAGE@-*.rpm

# !!!! first line of rule has to start with a hard (real) tab, not spaces
egs:
	$(MAKE) examples/tpm/tpm2_demo;

install-exec-local:	install-generic-config

install-generic-config:
	$(mkinstalldirs) $(DESTDIR)$(bindir)
	$(INSTALL_SCRIPT) @GENERIC_CONFIG@ $(DESTDIR)$(bindir)

uninstall-local:
	-rm -f $(DESTDIR)$(bindir)/@GENERIC_CONFIG@

merge-clean:
	@find ./ | $(GREP) \.gcda | xargs rm -f
	@find ./ | $(GREP) \.gcno | xargs rm -f
	@find ./ | $(GREP) \.gz | xargs rm -f
	@find ./ | $(GREP) \.orig | xargs rm -f
	@find ./ | $(GREP) \.rej | xargs rm -f
	@find ./ | $(GREP) \.rpm | xargs rm -f
	@find ./ | $(GREP) \.THIS | xargs rm -f
	@find ./ | $(GREP) \.OTHER | xargs rm -f
	@find ./ | $(GREP) \.BASE | xargs rm -f
	@find ./ | $(GREP) \~$$ | xargs rm -f

cppcheck:
	@if test "x@CPPCHECK@" = "xno"; then \
		echo "Error: cppcheck not found. Please install cppcheck."; \
		exit 1; \
	fi
	@CPPCHECK@ -f --enable=warning \
		--enable=portability --check-level=exhaustive \
		--suppress=invalidPrintfArgType_sint \
		--error-exitcode=89 --std=c89 \
		-I wolftpm src/ hal/ examples

# SBOM generation (CRA compliance).  The recipe is shared across the wolfSSL
# stack's autotools products in scripts/sbom.am; wolfTPM just declares what it
# is (a libwolftpm library that links wolfSSL/wolfCrypt) and includes it.
# WOLFSSL_DIR must point to a wolfssl source tree containing scripts/gen-sbom.
SBOM_PKGNAME      = wolftpm
SBOM_LICENSE_FILE = $(srcdir)/COPYING
SBOM_DEP_WOLFSSL  = yes

# wolfTPM records its feature macros in its own generated options header, so
# point gen-sbom at that header rather than at the compiler-derived defaults.
SBOM_OPTIONS_H    = $(abs_builddir)/wolftpm/options.h

# wolfTPM is GPLv3-or-later (per the per-file source headers: "either version 3
# of the License, or (at your option) any later version") or commercial.  Pin
# the header-accurate SPDX id here so the SBOM is correct regardless of the
# gen-sbom version's licence detection; commercial licensees can override it
# (e.g. LicenseRef-wolfSSL-Commercial).
SBOM_LICENSE_OVERRIDE ?= GPL-3.0-or-later

EXTRA_DIST += scripts/sbom.am

include scripts/sbom.am
