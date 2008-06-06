
TESTTRACEDIR=/opt/nstest/var/

all: test

test:
	find $(TESTTRACEDIR) | grep -e .eth -e .cap -e .pcap | grep -v summary | xargs ./test.sh -d


DISTFILES = Makefile pcap.vim test.sh

PACKAGE=pcaptxt
top_distdir = ..
VERSION:= $(shell cat ${distdir}/../VERSION)

distdir: $(DISTFILES)
	@list='$(DISTFILES)'; for file in $$list; do \
		if test -f $$file || test -d $$file; then d=.; else d=$(srcdir); fi; \
		dir=`echo "$$file" | sed -e 's,/[^/]*$$,,'`; \
		if test "$$dir" != "$$file" && test "$$dir" != "."; then \
			dir="/$$dir"; \
			$(mkinstalldirs) "$(distdir)$$dir"; \
		else \
			dir=''; \
		fi; \
		if test -d $$d/$$file; then \
			if test -d $(srcdir)/$$file && test $$d != $(srcdir); then \
				cp -pR $(srcdir)/$$file $(distdir)$$dir || exit 1; \
			fi; \
			cp -pR $$d/$$file $(distdir)$$dir || exit 1; \
		else \
			test -f $(distdir)/$$file \
			|| cp -p $$d/$$file $(distdir)/$$file \
			|| exit 1; \
		fi; \
	done


