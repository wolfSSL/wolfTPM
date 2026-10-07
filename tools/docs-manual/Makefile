.DEFAULT_GOAL := all
include ../common/common.am
include build/order.mk

SRC := src
MKDOC := mkdocs.yml
PDF := wolfTPM-Manual.pdf
DOXYBOOK := "$(WT_SOURCE)/tools/docs-manual/doxybook.cfg"

.PHONY: all api html-prep pdf-prep
all: pdf html

# Generate the API reference markdown straight from the in-tree headers.
# Doxyfile INPUT paths are repo-root relative, so run doxygen from WT_SOURCE and
# redirect its output into this manual dir to keep the source checkout clean.
api:
	$(Q)rm -rf api
	$(Q)mkdir -p api/md api/doxygen
	$(Q)cd "$(WT_SOURCE)" && ( cat docs/Doxyfile; \
		echo "OUTPUT_DIRECTORY=$(CURDIR)/api/doxygen"; \
		echo "GENERATE_HTML=NO"; echo "GENERATE_XML=YES"; echo "QUIET=YES" ) | doxygen -
	$(Q)doxybook2 --input api/doxygen/xml --output api/md --config $(DOXYBOOK)

# Doxybook2 output needs fixing for mkdocs: it swaps underscores for dashes in
# anchors, emits leading-slash links, and prefixes header-file titles.
html-prep: api
	$(Q)cp -a api/md/group* build/html/
	$(Q)cp -a api/md/*8h* build/html/
	$(Q)cp -a api/md/Classes build/html/
	$(Q)perl -i -pe 's#\]\(/Classes/#](#g' build/html/Classes/*.md
	$(Q)perl -i -pe "s/Classes\///g" build/html/Classes/*.md
	$(Q)perl -i -pe 's#\]\(/#](../#g' build/html/Classes/*.md
	$(Q)perl -i -pe 's#\]\(/#](#g' build/html/group* build/html/*8h*
	$(Q)perl -i -pe "s/(\]\([^)#]*#[a-z]+-)([^)]+?)(\))/\$$1.(\$$2=~tr#-#_#r).\$$3/ge" build/html/group* build/html/*8h* build/html/Classes/*.md
	$(Q)perl -i -pe "s/\/group_/group_/g" build/html/group* build/html/*8h*
	$(Q)perl -i -pe "s/\/tpm2_/tpm2_/g" build/html/group* build/html/*8h*
	$(Q)perl -i -pe "s/dox_comments\/header_files\///" build/html/*8h*

# Prepare the generated API pages for the PDF, then rewrite the hand-written
# pages' cross-links into single-document anchors (pdf-links skips the API pages).
pdf-prep: api
	$(Q)perl -i -pe "s/# /## /g" api/md/*.md
	$(Q)perl -i -pe "s/(\/group_.*|Classes\/struct.*|\/.*8h)\.md//g" api/md/*.md
	$(Q)perl -i -pe "s/^-(-)+$$//" api/md/*.md
	$(Q)perl -i -pe "s/^title:.*//" api/md/*.md
	$(Q)perl -i -pe "s/^Updated on.*//" api/md/*.md
	$(Q)perl -i -pe "s/^summary.*//" api/md/*.md
	$(Q)perl -i -pe "s/dox_comments\/header_files\///" api/md/*.md
	$(Q)perl -i -pe "s/^\\\\//" api/md/*.md
	$(Q)perl -i -pe "s/\\\\par/par/g" api/md/*.md
	$(Q)perl -i -pe "s/\[(.*?)\]\(Classes\/.*?.md\)/\[\1\]\(#typedef-\1\)/g" api/md/*.md
	$(Q)perl -i -pe "s/(?<=md\#function\-)(.*)(?=\))/\$$1=~s#-#_#gr/ge" api/md/*.md
	$(Q)perl -i -pe "s/(?<=md\#typedef\-)(.*)(?=\))/\$$1=~s#-#_#gr/ge" api/md/*.md
	$(Q)perl -i -pe "s/(?<=md\#enum\-)(.*)(?=\))/\$$1=~s#-#_#gr/ge" api/md/*.md
	$(Q)perl -i -pe 's!^\| enum\| (\*\*\[.*?\]\(.*?\)\*\*) \{(.*)\} \|\s*$$!do { my ($$name, $$vals) = ($$1, $$2); my @items = split(/, /, $$vals); my @chunks; my $$cur = ""; for my $$item (@items) { my $$cand = $$cur eq "" ? $$item : "$$cur, $$item"; if (length($$cand) > 220 && $$cur ne "") { push @chunks, $$cur; $$cur = $$item; } else { $$cur = $$cand; } } push @chunks, $$cur if $$cur ne ""; @chunks <= 1 ? "| enum| $$name { $$vals} |" : "| enum| $$name { $$chunks[0] |\n" . join("", map { "| | $$chunks[$$_]" . ($$_ == $$#chunks ? " }" : "") . " |\n" } 1..$$#chunks) }!ge if length > 2000' api/md/*.md
	$(Q)cp -a api/md/group* build/pdf/
	$(Q)cp -a api/md/*8h* build/pdf/
	$(Q)python3 "$(WT_SOURCE)/tools/docs_manual.py" pdf-links --documentation-root ..
