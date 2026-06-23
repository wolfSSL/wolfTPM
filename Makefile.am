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

# SBOM generation (CRA compliance)
SBOM_CDX     = wolftpm-$(PACKAGE_VERSION).cdx.json
SBOM_SPDX    = wolftpm-$(PACKAGE_VERSION).spdx.json
SBOM_SPDX_TV = wolftpm-$(PACKAGE_VERSION).spdx
sbomdir      = $(datadir)/doc/$(PACKAGE)

.PHONY: sbom install-sbom uninstall-sbom

sbom:
	@if test -z "$(PYTHON3)"; then \
	    echo ""; \
	    echo "ERROR: 'python3' not found in PATH. Cannot generate SBOM."; \
	    echo ""; \
	    exit 1; \
	fi
	@if test -z "$(PYSPDXTOOLS)"; then \
	    echo ""; \
	    echo "ERROR: 'pyspdxtools' not found in PATH. Cannot validate SBOM."; \
	    echo "       Install: pip install spdx-tools"; \
	    echo ""; \
	    exit 1; \
	fi
	@if test -z "$(WOLFSSL_DIR)"; then \
	    echo ""; \
	    echo "ERROR: WOLFSSL_DIR is not set. Cannot locate gen-sbom."; \
	    echo "       Set WOLFSSL_DIR to your wolfSSL source tree, e.g.:"; \
	    echo "         make sbom WOLFSSL_DIR=/path/to/wolfssl"; \
	    echo ""; \
	    exit 1; \
	fi
	@if test ! -f "$(WOLFSSL_DIR)/scripts/gen-sbom"; then \
	    echo ""; \
	    echo "ERROR: $(WOLFSSL_DIR)/scripts/gen-sbom not found."; \
	    echo "       Check that WOLFSSL_DIR points to a wolfSSL tree with SBOM support."; \
	    echo ""; \
	    exit 1; \
	fi
	rm -rf $(abs_builddir)/_sbom_staging
	$(MAKE) install DESTDIR=$(abs_builddir)/_sbom_staging
	$(PYTHON3) $(WOLFSSL_DIR)/scripts/gen-sbom \
	    --name wolftpm \
	    --version $(PACKAGE_VERSION) \
	    --supplier "wolfSSL Inc." \
	    --license-file $(srcdir)/LICENSE \
	    --options-h $(abs_builddir)/wolftpm/options.h \
	    --lib $(abs_builddir)/_sbom_staging$(libdir)/libwolftpm.so.@WOLFTPM_LIBRARY_VERSION_FIRST@.@WOLFTPM_LIBRARY_VERSION_SECOND@.@WOLFTPM_LIBRARY_VERSION_THIRD@ \
	    $(if $(SBOM_LICENSE_OVERRIDE),--license-override $(SBOM_LICENSE_OVERRIDE)) \
	    $(if $(SBOM_LICENSE_TEXT),--license-text $(SBOM_LICENSE_TEXT)) \
	    --cdx-out $(abs_builddir)/$(SBOM_CDX) \
	    --spdx-out $(abs_builddir)/$(SBOM_SPDX)
	rm -rf $(abs_builddir)/_sbom_staging
	$(PYSPDXTOOLS) --infile $(abs_builddir)/$(SBOM_SPDX) \
	    --outfile $(abs_builddir)/$(SBOM_SPDX_TV)

install-sbom: sbom
	$(MKDIR_P) $(DESTDIR)$(sbomdir)
	$(INSTALL_DATA) $(SBOM_CDX) $(DESTDIR)$(sbomdir)/
	$(INSTALL_DATA) $(SBOM_SPDX) $(DESTDIR)$(sbomdir)/
	$(INSTALL_DATA) $(SBOM_SPDX_TV) $(DESTDIR)$(sbomdir)/

uninstall-sbom:
	-rm -f $(DESTDIR)$(sbomdir)/$(SBOM_CDX)
	-rm -f $(DESTDIR)$(sbomdir)/$(SBOM_SPDX)
	-rm -f $(DESTDIR)$(sbomdir)/$(SBOM_SPDX_TV)

CLEANFILES += $(SBOM_CDX) $(SBOM_SPDX) $(SBOM_SPDX_TV)
