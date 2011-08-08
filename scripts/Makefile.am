# Obtained from bro/aux
## Process this file with automake to produce Makefile.in

built_srcs =

BUILT_SOURCES = $(built_srcs)

SUBDIRS = 

# files we want to delete with make maintainer-clean
MAINTAINERCLEANFILES = Makefile.in

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

