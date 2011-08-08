## Process this file with automake to produce Makefile.in

# snag the whole linux-include directory
EXTRA_DIST = AUTHORS ChangeLog COPYING INSTALL NEWS README VERSION

versiondir = $(prefix)/etc
dist_version_DATA = VERSION
chown = @CHOWN@

# srclib before src so we compile libhash
SUBDIRS = srclib src scripts
#SUBDIRS = src scripts doc

# files we want to delete with make maintainer-clean
MAINTAINERCLEANFILES = aclocal.m4 autoscan.log \
		config.h config.log configure Makefile.in \
		stamp-h1

# files we want to delete with make distclean
DISTCLEANFILES = $(CLEANFILES)

test:
	( cd src && $(MAKE) test )

docs:
	( cd doc && $(MAKE) doc )

doc-install:
	( cd doc && $(MAKE) doc-install )

# make sure we don't leak CVS/SVN or private policy files
dist-hook:
	rm -rf `find $(distdir) -name CVS`
	rm -rf `find $(distdir) -name .svn`
	rm -rf $(distdir)/autom4te.cache

# make sure all the dirs are correctly created and owned 
install-data-local:
	$(INSTALL) -d $(prefix)/logs
	$(INSTALL) -d $(prefix)/archive
	$(INSTALL) -d $(prefix)/var

release:
	./autogen.sh
	./configure
	$(MAKE) distcheck

