
all: mantest

mantest:
	groff -man -Tascii pcaptxt.1

manps:
	groff -man -Tps pcaptxt.1 > pcaptxt.ps

manhtml:
	man2html < pcaptxt.1 >pcaptxt.html

DISTFILES = Makefile pcaptxt.1


# don't touch anything below here 

# make sure we don't leak cvs or svn
dist-hook:
	rm -rf `find $(distdir) -name CVS`
	rm -rf `find $(distdir) -name svn`

distdir: $(DISTFILES)
	-chmod -R a+w $(distdir) >/dev/null 2>&1; rm -rf $(distdir)
	echo "YYY mkdir $(distdir)"
	mkdir $(distdir)
	@for file in $(DISTFILES); do \
		if test -f $$file; then d=.; else d=$(srcdir); fi; \
		dir=`echo "$$file" | sed -e 's,/[^/]*$$,,'`; \
		if test "$$dir" != "$$file" && test "$$dir" != "."; then \
			$(mkinstalldirs) "$(distdir)/$$dir"; \
		fi; \
		if test -d $$d/$$file; then \
			cp -pR $$d/$$file $(distdir) \
			|| exit 1; \
		else \
			test -f $(distdir)/$$file \
			|| cp -p $$d/$$file $(distdir)/$$file \
			|| exit 1; \
		fi; \
	done
	$(MAKE) $(AM_MAKEFLAGS) \
		top_distdir="${top_distdir}" \
		distdir="$(distdir)" \
		VERSION=$(VERSION) \
		dist-hook
	-find $(distdir) -type d ! -perm -777 -exec chmod a+rwx {} \; -o \
		! -type d ! -perm -444 -links 1 -exec chmod a+r {} \; -o \
		! -type d ! -perm -400 -exec chmod a+r {} \; -o \
		! -type d ! -perm -444 -exec $(SHELL) $(install_sh) -c -m a+r {} {} \; \
	|| chmod -R a+r $(distdir)


