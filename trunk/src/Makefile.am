## Process this file with automake to produce Makefile.in

bin_PROGRAMS=pcaptxt
pcaptxt_SOURCES=pcaptxt.c getline.c snscanf.c version.c
noinst_HEADERS=getline.h snscanf.h

LIBHASH_DIR = ../srclib/libhash-0.1/src/.libs
LIBHASH_INC = ../srclib/libhash-0.1/src

CCOPT = -W -Wall -Wno-unused -pedantic -static
INCLS = -I. -I$(top_srcdir)/src -I$(srcdir) -I$(top_builddir) -I$(LIBHASH_INC)
AM_CFLAGS = $(INCLS) $(CCOPT)
AM_CPPFLAGS = $(INCLS) $(CCOPT)

opt:
	@$(MAKE) $(MFLAGS) CCOPT="`echo $(CCOPT) | sed -e 's/-O2//;s/$$/ -O3/'`"

debug: 
	@$(MAKE) $(MFLAGS) CCOPT="`echo $(CCOPT) | sed -e 's/-O2/-O0/g;s/$$/ -g -Wall -DDEBUG/'`"

profile:
	@$(MAKE) $(MFLAGS) CCOPT="`echo $(CCOPT) | sed -e 's/$$/ -O0 -pg/'`" LDFLAGS="`echo $(LDFLAGS) | sed -e 's/$$/ -pg/'`"

mpatrol:
	@$(MAKE) $(MFLAGS) LIBS="`echo $(LIBS) | sed -e 's/$$/ -lmpatrol/'`"

version.c: ../VERSION
	@rm -f $@
	sed -e 's/.*/char version[] = "&";/' ../VERSION > $@


# files we want to delete with make maintainer-clean
MAINTAINERCLEANFILES = aclocal.m4 autoscan.log \
		config.h config.log configure Makefile.in \
		stamp-h1

# files we want to delete with make distclean
DISTCLEANFILES = version.c

# Files created in the src dir. 
MOSTLYCLEANFILES = $(BIF_FUNC_H) $(BIF_FUNC_DEF) $(BIF_FUNC_INIT) \
	$(BIF_NETVAR_H) $(BIF_NETVAR_DEF) $(BIF_NETVAR_INIT) \
	$(BRO_BIF) \
	$(BINPAC_H) $(BINPAC_CC) \
	$(DISTCLEANFILES)

LIBS = @LIBS@ -L$(LIBHASH_DIR) -lhash


# test infrastructure
TMP_TXT:=$(shell mktemp /tmp/trace-XXXXXX)
TMP_TXT2:=$(shell mktemp /tmp/trace-XXXXXX)
TMP_PCAP:=$(shell mktemp /tmp/trace-XXXXXX)

test2:
	echo "TMP_TXT is $(TMP_TXT)"
	echo "TMP_TXT is $(TMP_TXT)"

test:
	@echo "Running test"
	@echo "  ...creating a simple txt trace"
	@echo -e "header= pcapascii, little_endian= 1, magic= 0xa1b2c3d4, version_major= 0x0002, version_minor= 0x0004, thiszone= 0x00000000, sigfigs= 0x00000000, snaplen= 65000, linktype= 1\n\nheader= packet, index= 1, time= 1.000001, caplen= ok (42), len= ok (42)\n  header= ethernet, dst= 06:07:08:09:0a:0b, src= 00:01:02:03:04:05, proto= 0x0800\n  header= ip, v= 4, hlen= 5, tos= 0x00, len= ok (28), id= 0xabcd, fr_res= 0, fr_dont= 1, fr_more= 0, offset= +0, ttl= 64, proto= 17, sum= ok (0x7ef0), src= 1.2.3.4, dst= 5.6.7.8\n  header= udp, sport= 1111, dport= 2222, ulen= 8, sum= 0xa7c4\n" > $(TMP_TXT)
	@echo "  ...performing txt->pcap conversion"
	@./pcaptxt -s a -r $(TMP_TXT) -w $(TMP_PCAP)
	@echo "  ...performing pcap->txt conversion"
	@./pcaptxt -s p -r $(TMP_PCAP) -w $(TMP_TXT2)
	@echo "  ...diff'ing original and final text trace"
	@diff $(TMP_TXT) $(TMP_TXT2) && echo "test is ok" || echo "test is wrong"
	@rm -f $(TMP_TXT) $(TMP_PCAP) $(TMP_TXT2)

