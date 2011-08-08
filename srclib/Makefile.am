# Obtained from bro/aux
## Process this file with automake to produce Makefile.in

LIBHASH_VER = libhash-0.1
LIBHASH_LIB = $(LIBHASH_VER)/src/libhash.la

EXTRA_DIST = $(LIBHASH_VER).tar.gz

# don't compile libhash if they did a '--disable-libhash' to configure
if USE_LIBHASH
built_srcs =  $(LIBHASH_LIB)
else
built_srcs =
endif

BUILT_SOURCES = $(built_srcs)

SUBDIRS = 

# files we want to delete with make maintainer-clean
MAINTAINERCLEANFILES = aclocal.m4 autoscan.log \
		config.h config.log configure Makefile.in \
		stamp-h1

maintainerclean-hook:
	rm -rf `find $(distdir) -name .deps`

# files we want to delete with make distclean
DISTCLEANFILES = $(CLEANFILES) version.c

# Files created in the src dir. 
MOSTLYCLEANFILES = $(BIF_FUNC_H) $(BIF_FUNC_DEF) $(BIF_FUNC_INIT) \
		$(BIF_NETVAR_H) $(BIF_NETVAR_DEF) $(BIF_NETVAR_INIT) \
		$(BRO_BIF) \
		$(BINPAC_H) $(BINPAC_CC) \
		$(DISTCLEANFILES)


clean-local:
	rm -rf $(LIBHASH_VER)

$(LIBHASH_LIB): $(top_srcdir)/srclib/$(LIBHASH_VER).tar.gz
	@echo "Unpacking libhash sources"
	@gzip -d < $(top_srcdir)/srclib/$(LIBHASH_VER).tar.gz | tar xf -
	@echo "Building libhash"
	( cd $(LIBHASH_VER) && ./configure --prefix=$(prefix) $(HASHARGS) && $(MAKE) )
	@chmod -R 755 $(LIBHASH_VER)

