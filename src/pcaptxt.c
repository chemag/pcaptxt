/*
 * Copyright (c) 2007, Jose Maria Gonzalez (chema@cs.berkeley.edu)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the.
 *       distribution
 *     * Neither the name of the copyright holder nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS
 * IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER AND CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/* $Id$ */


/* pcaptxt - a pcap trace format converter
 *
 * pcaptxt converts pcap traces to other useful trace formats
 *
 * usage is:
 *      pcaptxt
 *                [-r filename]                                 # input
 *                [-w filename]                                 # output
 *                [-s conversion]                               # force conversion
 *                [-V]                                          # vim mode
 *                [-I]                                          # immediate mode
 *                [-q size]                                     # sequence table size
 *                [-Q]                                          # disable sequence table
 *                [-d]                                          # other
 *
 *
 * Input:
 * -r sets file trace to read (use filename="-" to read from stdin) [default]
 *
 * Output:
 * -w sets file trace to write (use filename="-" to write to stdout) [default]
 *
 * Output Format:
 * -s conversion: use <conversion> as the conversion mode
 *
 * Other:
 * -V sets vim mode
 * -V sets vim mode
 * -d sets debug mode
 * -h show help
 *
 */



/*
 * \todo Add a (forced) little endian mode for ascii->pcap conversions, so 
 *       that ascii->pcap conversions can be forced in big- or little-endian
 *       format (so far we use the little_endian field to decide)
 */



/*
 * \note vim introduces some problems when files end up in the EOL char 
 *       ('\n' aka LF in i386 boxes).
 *
 *       When writing a buffer to disk, and in nobinary mode, vim always 
 *       adds an EOL char after the last char in the buffer. When in 
 *       binary mode, the behavior depends on the endofline (&eol) 
 *       variable. If the variable is set to 1, an EOL is added. If 
 *       it's set to zero, no EOL is added.
 *
 *       The &eol variable is set when reading the file into the buffer. 
 *       If the file has as last char EOL, then &eol is set to 1. Otherwise 
 *       it's set to zero. 
 *
 *       The problem occurs when the trace being read and the one being
 *       written have a different &eol (one ends up in '\n' and the other
 *       does not). In this case, there's no way for us to tell vim to
 *       change its &eol variable (and therefore its behavior) to what 
 *       the text->trace command produced.
 *
 *       An interim solution, suggested by Yakov Lerner, is to (a) force 
 *       the &eol variable to zero (so no '\n' is ever added by vim), and 
 *       (b) ensure that pcaptxt in mode text->trace always repeats the last
 *       char (last_char) iff it's equal to '\n'. 
 *
 *       Thus, if the last is not '\n', vim will introduce no mayhem. If 
 *       it is, vim will get rid of the last '\n' char (the repeated one),
 *       and the final results will be correct. 
 *
 *       This behavior can be forced by setting vim_mode to 1 (use -V
 *       argument option).
 *
 *       More here:
 *         http://tech.groups.yahoo.com/group/vim/message/78100
 *         http://www.vim.org/htmldoc/editing.html#edit-binary
 *         http://www.vim.org/htmldoc/options.html#'endofline'
 *
 */

/*
 * \note We want to be able to use pcaptxt in immediate mode, so that
 *       it produces its output just after we introduce the input.
 *
 *       For the txt->pcap translation case, we have an input and an 
 *       output problem. For the input, pcaptxt considers a packet is 
 *       finished iff it has already seen the first header (frame 
 *       header) of the following packet. This means that the last
 *       text packet injected into pcaptxt will only be output when the
 *       user adds a new packet in the input. For the output, pcaptxt
 *       must flush the output descriptor after writing the packet. 
 *
 *       For the pcap->txt translation case, input depends on libpcap,
 *       so there's not too much we can do here. For the output, we 
 *       will flush it.
 *
 *       To solve this problem, we introduce an "immediate mode." In 
 *       immediate mode, txt->pcap translations, a blank line (one
 *       composed any number of ' ', '\t', '\r' chars) is considered 
 *       another packet end, and the output is flushed. For pcap->txt
 *       translations, the output is flushed.
 */

#include "config.h"


#define __USE_BSD

/* needed for getline() */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#if TIME_WITH_SYS_TIME
#	include <sys/time.h>
#	include <time.h>
#else
#	if HAVE_SYS_TIME_H
#		include <sys/time.h>
#	else
#		include <time.h>
#	endif
#endif

#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>

#ifdef HAVE_FCNTL_H
#	include <fcntl.h>
#endif

#include <errno.h>
#include <math.h>
#include <ctype.h>
#include <dlfcn.h>

#include <poll.h>
#ifdef __FreeBSD__
#	include <sys/event.h>
#endif


#include <pcap.h>

#ifdef __linux__
#	include <net/ethernet.h>
#	include <netinet/ether.h>
#endif

#include <netinet/in_systm.h>
#ifdef HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif

#define __FAVOR_BSD
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#ifdef HAVE_ARPA_INET_H
#	include <arpa/inet.h>
#endif

#if defined(__OpenBSD__)
#include <net/ethertypes.h>
#endif

#if defined(__OpenBSD__) || defined(__FreeBSD__)
#include <netinet/if_ether.h>
#endif



#include "snscanf.h"
#include "getline.h"
#include "hash.h"


/* default values */
#define DEFAULT_VIM_MODE 0
#define DEFAULT_IMMEDIATE_MODE 0
#define DEFAULT_DEBUG_LEVEL 0
#define DEFAULT_SEQ_TABLE_ENABLED 1
#define DEFAULT_SEQ_TABLE_SIZE 1024
#define DEFAULT_DIFF_MODE 0



#ifndef TCPDUMP_MAGIC
#define TCPDUMP_MAGIC 0xa1b2c3d4
#endif


#define SEP_FIELD '='
#define SEP_ENTRY ','


#define TEXT_GENERIC_HEADER "header"

#define TEXT_FORMAT_NAME "pcapascii"

#define MAX_PACKET_LENGTH 8096
#define MAX_IP_OPTIONS MAX_PACKET_LENGTH
#define MAX_TCP_OPTIONS MAX_PACKET_LENGTH
#define MAX_L7_LENGTH MAX_PACKET_LENGTH
#define MAX_REM_LENGTH MAX_PACKET_LENGTH
#define MAX_PACKET_ASCII_LENGTH (4*8096)

/* these macros are just so useful */
#ifndef MAX
#define MAX(x,y) (((x)>(y))?(x):(y))
#endif

#ifndef MIN
#define MIN(x,y) (((x)>(y))?(y):(x))
#endif

#define MAX_LINE_LENGTH 8192

FILE *debug_fs;

extern int errno;

extern int optind;

/* output file pointer */
FILE *out_fp;

char *in_file;
char *out_file;
int output_format;
int vim_mode;
int immediate_mode;
int diff_mode;
int debug;
char last_char[2];

#define CONVERSION_UNDEFINED 0
#define CONVERSION_PCAP_TO_ASCII 1
#define CONVERSION_ASCII_TO_PCAP 2
int conversion;

pcap_t *pcap_pd;
int packet_counter;
int line_number;


typedef struct
{
	char *s;
	size_t l; /* -1 means "doesn't exist" */
} string_t;


struct pcaptxt_timeval
{
	uint32_t tv_sec;
	uint32_t tv_usec;
};

/*
 * \note Packet header timestamps in pcap traces must be 2 32-bit values,
 *       namely seconds and microseconds. pcap_pkthdr (see pcap.h) uses 
 *       for the timestamp 'struct timeval', which is composed of 2 32-bit 
 *       tv_sec values on some platforms (32-bit platforms) and 64-bit 
 *       tv_sec values on other platforms (some/all 64-bit platforms). 
 *
 *       Note that this is not necessarily the case for the timestamps
 *       used in live capture, which will come in the local platform 
 *       'struct timeval' format. It is the savefile task to fix this 
 *       problem.
 *
 * \sa /usr/include/pcap-int.h
 * \sa /usr/include/pcap.h
 */
struct pcaptxt_pkthdr
{
	struct pcaptxt_timeval ts;
	bpf_u_int32 caplen;
	bpf_u_int32 len;
};


typedef struct
{
	int valid;
	int index;
	struct pcaptxt_pkthdr frame;
	uint8_t buffer[MAX_PACKET_LENGTH];
	/* l2 */
	uint8_t *l2;
	uint32_t l2_hlen;
	int l3_proto;
	/* IP */
	uint8_t *l3;
	struct ip *ip;
	uint8_t *ip_opts;
	struct ip6_hdr *ip6;
	uint32_t l3_hlen;
	uint32_t l3_len; /* actual l3_len in the packet (snaplen) */
	uint32_t ip_optlen;
	int ip_sum_valid; /* ip cksum validity */
	int l4_proto;
	/* l4 */
	uint8_t *l4;
	struct tcphdr *tcp;
	uint8_t *tcp_opts;
	struct udphdr *udp;
#if defined(__OpenBSD__) || defined(__FreeBSD__)
#define icmphdr icmp
#endif
	struct icmphdr *icmp;
	uint32_t l4_hlen;
	uint32_t l4_len; /* actual l4_len in the packet (snaplen) */
	uint32_t tcp_optlen;
	int tcp_sum_valid; /* tcp cksum validity */
	/* l7 */
	uint8_t *l7;
	uint32_t l7_len; /* actual l7_len in the packet (snaplen) */
	/* remaining */
	uint8_t *rem;
	uint32_t rem_len;
} packet_t;



#define KEYWORD_OK "ok"
#define VALUE_OK 0xffffffff


typedef enum
{
	TYPE_STRING,
	TYPE_INT,
	TYPE_INTEXT,
	TYPE_UINT,
	TYPE_UINTEXT,
	TYPE_DOUBLE,
	TYPE_TWOUINTS,
	TYPE_ETHADDR,
	TYPE_IPADDR,
	TYPE_IPADDR6,
	TYPE_TCPFLAGS,
	TYPE_INVALID
} type_t;


#define HEADER_FILE 0
#define HEADER_FRAME 1
#define HEADER_L2 2
#define HEADER_ETHERNET 3
#define HEADER_L3 4
#define HEADER_IP 5
#define HEADER_IP6 6
#define HEADER_L4 7
#define HEADER_TCP 8
#define HEADER_UDP 9
#define HEADER_ICMP 10
#define HEADER_L7 11
#define HEADER_REM 12
#define HEADER_INIT 13


char *valid_states_s[] =
{
	TEXT_FORMAT_NAME,
	"packet",
	"l2",
	"ethernet",
	"l3",
	"ip",
	"ip6",
	"l4",
	"tcp",
	"udp",
	"icmp",
	"l7",
	"rem",
	NULL
};


char *txt_label_file_header[] =
{
	"little_endian",
	"magic",
	"version_major",
	"version_minor",
	"thiszone",
	"sigfigs",
	"snaplen",
	"linktype",
	NULL
};


char *txt_label_frame[] =
{
	"index",
	"time",
	"caplen",
	"len",
	NULL
};


char *txt_label_l2_header[] =
{
	"contents",
	NULL
};


char *txt_label_ethernet_header[] =
{
	"dst",
	"src",
	"proto",
	NULL
};


char *txt_label_l3_header[] =
{
	"contents",
	NULL
};


char *txt_label_ip_header[] =
{
	"v",
	"hlen",
	"tos",
	"len",
	"id",
	"fr_res",
	"fr_dont",
	"fr_more",
	"offset",
	"ttl",
	"proto",
	"sum",
	"src",
	"dst",
	"options",
	NULL
};


char *txt_label_ip6_header[] =
{
	"flow",
	"plen",
	"next",
	"hops",
	"src",
	"dst",
	NULL
};


char *txt_label_l4_header[] =
{
	"contents",
	NULL
};


char *txt_label_tcp_header[] =
{
	"sport",
	"dport",
	"seq",
	"ack",
	"off",
	"x2",
	"flags",
	"win",
	"sum",
	"urp",
	"options",
	NULL
};


char *txt_label_udp_header[] =
{
	"sport",
	"dport",
	"ulen",
	"sum",
	NULL
};


char *txt_label_l7_header[] =
{
	"contents",
	NULL
};


char *txt_label_rem_header[] =
{
	"contents",
	NULL
};



/* common packet objects */
int packet_pending_packet = 0;
int little_endian;
struct pcap_file_header file_hdr;
packet_t the_packet;

char remaining_label[MAX_PACKET_ASCII_LENGTH];
char remaining_contents[MAX_PACKET_ASCII_LENGTH];
string_t rem_label = {remaining_label, 0};
string_t rem_contents = {remaining_contents, 0};

int cur;
int next;

typedef enum
{
	TYPE_EMPTY,
	TYPE_LEFT,
	TYPE_RIGHT,
	TYPE_FULL
} line_type_t;

int line_state;



extern char version[];



/* main functions */
static void usage();
int parse_args (int argc, char **argv);

/* main converters */
void ascii_to_pcap(char *in_file, char *out_file);
void pcap_to_ascii(char *in_file, char *out_file);

/* pcap get functions */
void pcap_get_packet (uint8_t *user, const struct pcap_pkthdr *chdr,
		const uint8_t *cpkt);
int pcap_get_file_header(char *filename, struct pcap_file_header *hdr);
int pcap_get_frame (const struct pcap_pkthdr *hdr, packet_t* packet);
int pcap_get_l2(packet_t *packet);
int pcap_get_l3(packet_t *packet);
int pcap_get_ip (packet_t* packet);
int pcap_get_ip6 (packet_t* packet);
int pcap_get_l4(packet_t *packet);
int pcap_get_tcp (packet_t* packet);
int pcap_get_udp (packet_t* packet);
int pcap_get_icmp (packet_t* packet);
int pcap_get_l7 (packet_t* packet);
int pcap_get_rem (packet_t* packet);

/* pcap put functions */
int pcap_put_file_header (FILE *fp, struct pcap_file_header *hdr);
void pcap_put_packet(packet_t* packet, FILE *fp);
void pcap_postprocess_packet(char *buffer, packet_t* packet);
int pcap_put_frame (char *buf, packet_t *packet);
int pcap_put_l2 (char *buf, packet_t *packet);
int pcap_put_l3 (char *buf, packet_t *packet);
int pcap_put_ip (char *buf, packet_t *packet);
int pcap_put_ip6 (char *buf, packet_t *packet);
int pcap_put_l4 (char *buf, packet_t *packet);
int pcap_put_tcp (char *buf, packet_t *packet);
int pcap_put_udp (char *buf, packet_t *packet);
int pcap_put_icmp (char *buf, packet_t *packet);
int pcap_put_l7 (char *buf, packet_t *packet);
int pcap_put_rem (char *buf, packet_t *packet);


/* text functions */
char *sprintf_string(string_t *str);
int getxvalue(char c);
int look_for_string(char **haystack, char *needle);
char *addr_to_string (uint32_t addr);
char* dump_ethaddr (uint8_t *addr);
char *encode_string (unsigned char *pkt, int len);
char *escape_string (unsigned char *pkt, int len);
int unescape_string (char *sin, int sinlen, char* buf, int buflen);
int unescape_string_t (string_t *sin, char* buf, int buflen);
int getval_string (type_t type, char *str, void *value);


/* text put functions */
int txt_put_packet(FILE *fp, packet_t* packet);
int txt_put_file_header(FILE *fp, struct pcap_file_header *hdr);
int txt_put_frame(FILE *fp, packet_t* packet);
int txt_put_l2 (FILE *fp, packet_t* packet);
int txt_put_ethernet (FILE *fp, packet_t* packet);
int txt_put_l3 (FILE *fp, packet_t* packet);
int txt_put_ip (FILE *fp, packet_t* packet);
int txt_put_ip6 (FILE *fp, packet_t* packet);
int txt_put_l4 (FILE *fp, packet_t* packet);
int txt_put_tcp (FILE *fp, packet_t* packet);
int txt_put_udp (FILE *fp, packet_t* packet);
int txt_put_icmp (FILE *fp, packet_t* packet);
int txt_put_l7 (FILE *fp, packet_t* packet);
int txt_put_rem (FILE *fp, packet_t* packet);
void txt_put_string (FILE *fp, char *str, ...);

/* text get functions */
int txt_get_change_state(int cur, char *buf, packet_t* packet);
int txt_get_pair(char *line, int state, string_t *left, string_t *right,
		string_t *rem);
void txt_get_dispatch(string_t *left, string_t *right, packet_t* packet);
int txt_get_file_header(char *lbuf, char *rbuf, struct pcap_file_header *hdr);
int txt_get_frame(char *lbuf, char *rbuf, packet_t *packet);
int txt_get_l2(char *lbuf, char *rbuf, int rlen, packet_t *packet);
int txt_get_ethernet(char *lbuf, char *rbuf, packet_t *packet);
int txt_get_l3(char *lbuf, char *rbuf, int rlen, packet_t *packet);
int txt_get_ip(char *lbuf, char *rbuf, int rlen, packet_t *packet);
int txt_get_ip6(char *lbuf, char *rbuf, int rlen, packet_t *packet);
int txt_get_l4(char *lbuf, char *rbuf, int rlen, packet_t *packet);
int txt_get_tcp(char *lbuf, char *rbuf, int rlen, packet_t *packet);
int txt_get_udp(char *lbuf, char *rbuf, packet_t *packet);
int txt_get_icmp(char *lbuf, char *rbuf, packet_t *packet);
int txt_get_l7(char *lbuf, char *rbuf, int rlen, packet_t *packet);
int txt_get_rem(char *lbuf, char *rbuf, int rlen, packet_t *packet);


uint16_t ip_checksum(uint8_t *ip_hdr);
uint16_t tcp_checksum(uint8_t *ip_hdr);

/* error function */
void pcaptxt_error (int code, char *str, ...);
static char* my_strerror(int errnum);


/* other functions */
int do_fwrite(FILE *fp, uint8_t *buf, int len);
void string_append(string_t *str, string_t *post);
void string_reset(string_t *str);
struct timeval timeval_diff (struct timeval *ts2, struct timeval *ts1);
void packet_reset(packet_t *p);

uint32_t swapl(uint32_t i);
uint16_t swaps(uint16_t i);


/* sequence number hash table */
#define SEQ 0
#define ACK 1
int seq_table_enabled;
int seq_table_len;
hash_table_t *ht;
hash_function_t *hf;
int seq_init(int len);
void seq_fini();
uint32_t seq_check(packet_t* packet, int type);


int pcaptxt_get_linklen (int datalink);

/*
 * XXX add to doc:
 * XXX -q 256 means size the seq# processing table [default 1024]
 * XXX -Q means disable seq# processing
 */



/**
 * \brief Main function
 * 
 * \param[in] argc Argument counter
 * \param[in] argv Arguments
 * \retval int Error code (0 if OK, <0 if problems)
 */
int main (int argc, char **argv)
{
	debug_fs = stdout;

	/* init packet&line counter */
	packet_counter = 1;
	line_number = 0;

	/* parse argument line */
	(void)parse_args (argc, argv);

	switch (conversion)
		{
		case CONVERSION_ASCII_TO_PCAP:
			ascii_to_pcap(in_file, out_file);
			break;
		case CONVERSION_PCAP_TO_ASCII:
			pcap_to_ascii(in_file, out_file);
			break;
		default:
			fprintf (stderr, "Error [%s]: Unknown conversion\n", __func__);
			exit(-1);
		}

	exit(0);
}



/**
 * \brief Usage printf
 * 
 * A basic usage function. it also exits.
 * 
 */
void usage()
{
	fprintf(stderr, "pcaptxt version %s\n", version);

	fprintf(stderr, "usage: pcaptxt [options]\n");
	fprintf(stderr, "where options are:\n");

	fprintf(stderr, "  i/o:\n");
	fprintf(stderr, "\t-r filename\tread from filename (use \"-\" to read "
			"from stdin)\n");
	fprintf(stderr, "\t-w filename\twrite to filename (use \"-\" to write "
			"to stdout)\n");
	fprintf(stderr, "  other:\n");
	fprintf(stderr, "\t-s [a|p]\tforce conversion, with source being "
			"ascii (a) or pcap (p)\n");
	fprintf(stderr, "\t-q <size>\tSequence table size\n");
	fprintf(stderr, "\t-Q\t\tDisable sequence table\n");
	fprintf(stderr, "\t-V\t\tvim mode\n");
	fprintf(stderr, "\t-I\t\timmediate mode\n");
	fprintf(stderr, "\t-v\t\tprint version and exit\n");
	fprintf(stderr, "\t-d\t\tdebug mode\n");
	fprintf(stderr, "\t-h\t\tthis help\n");
	exit(1);
}




/**
 * \brief Argument parsing
 * 
 * A basic argument parsing function
 * 
 * \param[in] argc Argument counter
 * \param[in] argv Arguments
 * \retval int Error code (0 if OK, <0 if problems)
 */
int parse_args (int argc, char **argv)
{
	int arg;

	/* set defaults */
	in_file = "-";
	out_file = "-";
	output_format = 0;
	vim_mode = DEFAULT_VIM_MODE;
	immediate_mode = DEFAULT_IMMEDIATE_MODE;
	debug = DEFAULT_DEBUG_LEVEL;
	conversion = CONVERSION_UNDEFINED;
	seq_table_enabled = DEFAULT_SEQ_TABLE_ENABLED;
	seq_table_len = DEFAULT_SEQ_TABLE_SIZE;
	diff_mode = DEFAULT_DIFF_MODE;


	/* parse command-line arguments */
	while ((arg = getopt(argc, argv, "r:w:f:s:Qq:VIDvdh?")) != -1)
		{
		switch (arg)
			{
			/* input */
			case 'r':
				in_file = optarg;
				break;

			/* output */
			case 'w':
				out_file = optarg;
				break;

			case 'f':
				output_format = atoi(optarg);
				break;

			case 'V':
				vim_mode = !vim_mode;
				break;

			case 'I':
				immediate_mode = !immediate_mode;
				break;

			case 'D':
				diff_mode = !diff_mode;
				break;

			case 's':
				if ( optarg[0] == 'a' )
					/* source is ascii */
					conversion = CONVERSION_ASCII_TO_PCAP;
				else if ( optarg[0] == 'p' )
					/* source is pcap */
					conversion = CONVERSION_PCAP_TO_ASCII;
				else
					{
					/* invalid conversion */
					fprintf(stderr, "Error [%s]: invalid conversion (%s)\n", __func__,
							optarg);
					exit(-1);
					}
				break;

			/* seq table */
			case 'Q':
				seq_table_enabled = 0;
				break;

			case 'q':
				seq_table_enabled = 1;
				seq_table_len = atoi(optarg);
				break;

			/* other */
			case 'v':
				fprintf(stderr, "%s version %s\n", argv[0], version);
				exit(0);
				break;

			case 'd':
				debug += 1;
				break;

			case 'h':
			case '?':
			default:
				usage();
				break;
			}
		}


	if ( conversion == CONVERSION_UNDEFINED )
		{
		/* fix conversion */
		int len;
		char *s;
		if ( in_file != NULL && (len = strlen(in_file)) > 4 )
			{
			/* try to get info from in_file extension */
			s = in_file + len - 4;
			if ( strcasecmp(s, ".txt") == 0 )
				conversion = CONVERSION_ASCII_TO_PCAP;
			else if ( strcasecmp(s, ".eth") == 0 )
				conversion = CONVERSION_PCAP_TO_ASCII;
			s = in_file + len - 5;
			if ( strcasecmp(s, ".pcap") == 0 )
				conversion = CONVERSION_PCAP_TO_ASCII;
			}
		}

	if ( conversion == CONVERSION_UNDEFINED )
		{
		/* conversion still undefined */
		/* fix conversion */
		int len;
		char *s;
		if ( out_file != NULL && (len = strlen(out_file)) > 4 )
			{
			/* try to get info from out_file extension */
			s = out_file + len - 4;
			if ( strcasecmp(s, ".txt") == 0 )
				conversion = CONVERSION_ASCII_TO_PCAP;
			else if ( strcasecmp(s, ".eth") == 0 )
				conversion = CONVERSION_PCAP_TO_ASCII;
			s = out_file + len - 5;
			if ( strcasecmp(s, ".pcap") == 0 )
				conversion = CONVERSION_PCAP_TO_ASCII;
			}
		}

#ifdef DEBUG
	fprintf (debug_fs, "Conversion is %i\n", conversion);
#endif

	if ( seq_table_enabled )
		/* init seq table */
		seq_init(seq_table_len);

	return 0;
}



void pcap_to_ascii(char *in_file, char *out_file)
{
	packet_t *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	int pcap_fd;

	/* use the_packet */
	packet = &the_packet;

	/* peek packet header from input */
	(void)pcap_get_file_header(in_file, &file_hdr);

	/* set input in pcap */
	if ( ! (pcap_pd = pcap_open_offline((char*) in_file, errbuf)) )
		pcaptxt_error(-1, "pcap_open_offline: %s\n", errbuf);
	pcap_fd = fileno(pcap_file(pcap_pd));

	/* get output desc */
	if ( (out_file == NULL) || strncmp (out_file, "-", 1) == 0 )
		/* use stdout */
		out_fp = stdout;
	else
		{
		/* open the file pointer for writing */
		out_fp = fopen(out_file, "w+");
		if ( out_fp == NULL )
			pcaptxt_error (-1, "Error opening %s: %s\n", out_file, my_strerror(errno));
		}

	/* dump pcap header */
	txt_put_file_header(out_fp, &file_hdr);

	/* read traffic */
	/* packets are counted in natural order */
	packet_counter = 1;
	while (pcap_fd != -1)
		{
		/* reset packet contents */
		packet_reset(packet);
		packet->index = packet_counter;
		if (pcap_dispatch(pcap_pd, 1, pcap_get_packet, (void*)&the_packet) < 0)
			{
			if ( errno == 0 )
				/* truncated file => mark it as dry */
				pcap_fd = -1;
			else
				pcaptxt_error(-1, "pcap_dispatch: %s\n", pcap_geterr(pcap_pd));
			}
		if ( feof(pcap_file(pcap_pd)) )
			pcap_fd = -1;
		/* count the packet */
		++packet_counter;
		}


	/* close trace */
	pcap_close(pcap_pd);

	/* close output */
	fclose(out_fp);

	return;
}



void ascii_to_pcap(char *in_file, char *out_file)
{
	packet_t *packet;
	FILE *in_fp;
	char *line;
	size_t len;
	string_t left, right, remaining;


	/* use the_packet */
	packet = &the_packet;

	/* get input desc */
	if ( (in_file == NULL) || strncmp (in_file, "-", 1) == 0 )
		/* use stdin */
		in_fp = stdin;
	else
		{
		/* open input file */
		in_fp = fopen(in_file, "r");
		if ( in_fp == NULL )
			pcaptxt_error (-1, "Error opening %s: %s\n", in_file, my_strerror(errno));
		}

	/* get output desc */
	if ( (out_file == NULL) || strncmp (out_file, "-", 1) == 0 )
		/* use stdout */
		out_fp = stdout;
	else
		{
		/* open the file pointer for writing */
		out_fp = fopen(out_file, "w+");
		if ( out_fp == NULL )
			pcaptxt_error (-1, "Error opening %s: %s\n", out_file, my_strerror(errno));
		}


	/* initialize state */
	memset(&file_hdr, 0, sizeof(struct pcap_file_header));
	packet_reset(packet);
	cur = HEADER_INIT;
	line_state = TYPE_EMPTY;
	string_reset(&rem_label);
	string_reset(&rem_contents);


	/* read line, put line */
	while (!feof(in_fp) && my_getln(in_fp, &line, &len) && ++line_number)
		{
		/* consume all initial blanks */
		while ( isspace(line[0]) ) { ++line; --len; }

		if ( immediate_mode && len == 0 )
			/* an empty line in immediate mode implies a packet end */
			pcap_put_packet(packet, out_fp);

		/* consume line */
		while ( len > 0 )
			{
			/* consume all initial blanks */
			while ( isspace(line[0]) ) { ++line; --len; }

			/* skip comment lines */
			if ( line[0] == '#' )
				continue;

			/* get a value pair */
			line_state = txt_get_pair(line, line_state, &left, &right, &remaining);
			switch ( line_state )
				{
				case TYPE_FULL:
					/* coalesce label */
					if ( left.l > 0 )
						{
						string_append(&rem_label, &left);
						string_reset(&left);
						}
					/* coalesce contents */
					if ( right.l > 0 )
						{
						string_append(&rem_contents, &right);
						string_reset(&right);
						}
					/* full pair */
					txt_get_dispatch(&rem_label, &rem_contents, packet);
					line_state = TYPE_EMPTY;
					string_reset(&rem_label);
					string_reset(&rem_contents);
					break;

				case TYPE_RIGHT:
					/* coalesce label */
					if ( left.l > 0 )
						{
						string_append(&rem_label, &left);
						string_reset(&left);
						}
					/* coalesce contents */
					if ( right.l > 0 )
						{
						string_append(&rem_contents, &right);
						string_reset(&right);
						}
					/* set state straigth */
					line_state = TYPE_RIGHT;
					break;

				case TYPE_LEFT:
					/* coalesce label */
					if ( left.l > 0 )
						{
						string_append(&rem_label, &left);
						string_reset(&left);
						}
					/* set state straigth */
					line_state = TYPE_LEFT;
					break;
				}

			/* get remaining string in the line */
			line = remaining.s;
			len = remaining.l;
			}
		}


	/* consume dangling line */
	if ( line_state == TYPE_RIGHT )
		{
		/* coalesce label */
		if ( left.l > 0 )
			{
			string_append(&rem_label, &left);
			string_reset(&left);
			}
		/* coalesce contents */
		if ( right.l > 0 )
			{
			string_append(&rem_contents, &right);
			string_reset(&right);
			}
		/* set state straigth */
		line_state = TYPE_FULL;
		/* full pair */
		txt_get_dispatch(&rem_label, &rem_contents, packet);
		line_state = TYPE_EMPTY;
		string_reset(&rem_label);
		string_reset(&rem_contents);
		}

	/* dispatch dangling packet */
	pcap_put_packet(packet, out_fp);

	/* close input */
	fclose(in_fp);

	/* close output */
	if ( vim_mode && (last_char[0] == '\n') )
		(void) do_fwrite (out_fp, (uint8_t *)last_char, 1);
	fclose(out_fp);

	return;
}



/* error functions */
void pcaptxt_error (int code, char *str, ...)
{
	/* printf the error message */
	va_list ap;
	va_start (ap, str);
	fprintf (stderr, str, ap);
	va_end(ap);

	/* exit if requested */
	if ( code != 0 )
		exit(code);

	return;
}




/**
 * \brief A portable strerror
 * 
 * Obtained from bro
 * 
 * \param[in] errnum Error number
 * \retval char* Error string
 */
static char* my_strerror(int errnum)
{
#if HAVE_STRERROR
	extern char *strerror(int);
	return strerror(errnum);
#else
	static char errnum_buf[32];
	snprintf(errnum_buf, sizeof(errnum_buf), "errno %d", errnum);
	return errnum_buf;
#endif
}



/**
 * \brief Main pcap per-packet callback
 * 
 * \param[in] user Packet counter
 * \param[in] chdr Packet header
 * \param[in] cpkt Packet contents
 * \retval none
 */
void pcap_get_packet (uint8_t *user, const struct pcap_pkthdr *chdr,
		const uint8_t *cpkt)
{
	uint8_t *pkt;
	packet_t *packet;
	unsigned int pi;

	/* get packet (user pointer) */
	packet = (packet_t *)user;

	/* get frame info */
	(void)pcap_get_frame (chdr, packet);

	/* un-const'ize the packet */
	pkt = (uint8_t *)cpkt;
	pi = 0;

	/* copy packet to buffer */
	memcpy ((void *)&packet->buffer, pkt, htonl(packet->frame.caplen));

	/* get l2 header */
	if ( pcap_get_l2(packet) < 0 )
		{
		/* no known L2 packet */
		fprintf (stderr, "Error [%s]: Invalid L2 packet\n", __func__);
		exit(-1);
		}
	pi += packet->l2_hlen;

	/* get L3 header */
	switch ( packet->l3_proto )
		{
		case ETH_P_IP:
			/* get IP header */
			(void) pcap_get_ip(packet);
			break;

		case ETH_P_IPV6:
			/* get IP6 header */
			(void) pcap_get_ip6(packet);
			break;

		default:
			(void) pcap_get_l3(packet);
			break;
		}
	pi += packet->l3_hlen;

	/* get L4 header */
	if ( packet->l4_len > 0 )
		{
		/* dump transport header */
		switch ( packet->l4_proto )
			{
			case IPPROTO_TCP:
				/* get TCP header */
				(void) pcap_get_tcp(packet);
				break;

			case IPPROTO_UDP:
				/* get UDP header */
				(void)pcap_get_udp(packet);
				break;

			case IPPROTO_ICMP:
#ifdef DONT_IGNORE_ICMP
				/* get ICMP header */
				(void)pcap_get_icmp(packet);
				break;
#endif

			default:
				(void) pcap_get_l4(packet);
				break;
			}
		pi += packet->l4_hlen;
		}

	/* get L7 contents */
	packet->l7_len = packet->l4_len - packet->l4_hlen;
	(void) pcap_get_l7(packet);
	pi += packet->l7_len;

	/* get remaining data */
	(void) pcap_get_rem(packet);
	pi += packet->rem_len;

	/* put packet if it exists */
	if ( packet->valid )
		(void) txt_put_packet(out_fp, packet);

	return;
}





/**
 * \brief Get a pcap file header
 *
 * This functions gets a pcap file header from a trace file. It opens the
 * file, reads sizeof(struct pcap_file_header) bytes, and then unmarshalls
 * the contents into a header struct
 *
 * \param[in] filename File name
 * \param[in,out] hdr Header struct
 * \retval int 0 if OK, <0 if problems
 * \sa pcap_get_file_header_from_desc
 */
int pcap_get_file_header(char *filename, struct pcap_file_header *hdr)
{
	FILE *fp;
	unsigned char buffer[1024];
	int i;


	if (filename[0] == '-' && filename[1] == '\0')
		{
		/* fpeek header bytes from stdin */
		fp = stdin;
		/*
		 * \note According to the GNU C library, "only one pushback is
		 *       guaranteed" with ungetc(). While some operating systems
		 *       let you push back multiple characters (including when
		 *       reading from the stdin), it does not need to be the
		 *       case.
		 *       Moreover, some OSs consider lines as flush stdin points, so
		 *       that ungetc() does not work after popping a '\n' char.
		 */
		for (i=0; i<(int)sizeof(struct pcap_file_header); ++i)
			buffer[i] = fgetc(stdin);
		for (i=sizeof(struct pcap_file_header)-1; i>=0; --i)
			/*
			 * \note It is important for buffer to be cast to unsigned char
			 * See http://gcc.gnu.org/ml/gcc-patches/2000-02/msg00873.html
			 */
			(void)ungetc(buffer[i],stdin);
		}
	else
		{
		/* open the file */
		if ( (fp = fopen(filename, "r")) == NULL )
			{
			/* invalid trace file */
			fprintf (stderr, "Error [%s]: can't open trace file %s\n", __func__,
					filename);
			exit(-1);
			}
		/* read the header bytes */
		fread(buffer, sizeof(struct pcap_file_header), 1, fp);
		}


	/* memcpy the file header */
	memcpy ((void *)hdr, buffer, sizeof(struct pcap_file_header));

	/* check trace and endianism */
	if ( htonl(hdr->magic) == TCPDUMP_MAGIC )
		/* this trace is written in right (big-endian) format */
		little_endian = 0;
	else if ( htonl(swapl(hdr->magic)) == TCPDUMP_MAGIC )
		/* this trace was written in wrong (little-endian) format */
		little_endian = 1;
	else
		{
		/* invalid trace file */
		fprintf (stderr, "Error [%s]: Invalid trace file %s (begins with 0x%08x)\n",
				__func__, filename, hdr->magic);
		exit(-1);
		}


	/* we keep all data in network order */
	if ( little_endian )
		{
		/* this trace was written in wrong (little-endian) format */
		hdr->magic = htonl(hdr->magic);
		hdr->version_major = htons(hdr->version_major);
		hdr->version_minor = htons(hdr->version_minor);
		hdr->thiszone = htonl(hdr->thiszone);
		hdr->sigfigs = htonl(hdr->sigfigs);
		hdr->snaplen = htonl(hdr->snaplen);
		hdr->linktype = htonl(hdr->linktype);
		}

	if ( fp != stdin )
		/* close the file */
		fclose(fp);

	return 0;
}



int pcap_get_frame (const struct pcap_pkthdr *hdr, packet_t* packet)
{
	int caplen;

	/* keep all data in network order */
	packet->frame.ts.tv_sec = ntohl(hdr->ts.tv_sec);
	packet->frame.ts.tv_usec = ntohl(hdr->ts.tv_usec);
	packet->frame.len = ntohl(hdr->len);

	/* ensure packet is not larger than the buffer */
	caplen = hdr->caplen;
	caplen = MIN(caplen, MAX_PACKET_LENGTH);
	if ( hdr->caplen > MAX_PACKET_LENGTH )
		fprintf (stderr, "Error [%s]: L2 packet too big (%i)\n", __func__,
				hdr->caplen);
	packet->frame.caplen = ntohl(caplen);

	/* mark the packet as valid */
	packet->valid = 1;

	return 0;
}



/**
 * \brief Get L2 header
 * 
 * \param[in,out] packet Packet structure to fill
 * \retval int Error code (0 if OK, <0 if problems)
 */
int pcap_get_l2(packet_t *packet)
{
	/* point L2 header pointer */
	packet->l2 = packet->buffer;

	/* get L2 header length */
	packet->l2_hlen = pcaptxt_get_linklen (ntohl(file_hdr.linktype));
	packet->l2_hlen = MIN(packet->l2_hlen, htonl(packet->frame.caplen));
	packet->l2_hlen = MAX(packet->l2_hlen, 0);

	/* check if we know how to interpret the L2 */
	switch (ntohl(file_hdr.linktype))
		{
		case DLT_EN10MB:
			{
			/* ethernet headers are easy to interpret */
			struct ether_header *eth = (struct ether_header *)packet->l2;
			packet->l3_proto = (int) ntohs(eth->ether_type);
			break;
			}

		case DLT_LINUX_SLL:
			/* linux cooked socket */
			packet->l3_proto = (int) ntohs(*(uint16_t *)(packet->l2+14));
			break;

		case DLT_RAW:
			/* raw IP (no link layer) */
			packet->l3_proto = ETH_P_IP;
			break;

		case DLT_NULL:
		case DLT_FDDI:
		default:
			/* unknown structure datalink: won't try to interpret it */
			packet->l3_proto = ETH_P_IP;
			break;
		}

	return 0;
}



/* don't know how to dump this L3: assume remaining is L3 */
int pcap_get_l3(packet_t *packet)
{
	/* point L3 header pointer */
	packet->l3 = packet->buffer + packet->l2_hlen;

	/* get the actual l3_len in the packet */
	packet->l3_len = htonl(packet->frame.caplen) - packet->l2_hlen;

	/* unknown L3 header -> everything is header */
	packet->l3_hlen = packet->l3_len;

	/* no L4 */
	packet->l4_proto = -1;
	packet->l4_len = 0;

	return 0;
}



int pcap_get_ip (packet_t* packet)
{
	/* point IP header pointers */
	packet->ip = (struct ip *)(packet->buffer + packet->l2_hlen);
	packet->ip_opts = packet->buffer + packet->l2_hlen + sizeof(struct ip);

	/* check we're happy with the IP header */
	if (
			/* we only know how to process IPv4 */
			(packet->ip->ip_v != 4) ||
			/* IP headers should be at least 20-byte long */
			/* from the IP spec (RFC 791):
			 *   "Internet Header Length is the length of the internet header in
			 *    32 bit words, and thus points to the beginning of the data. 
			 *    Note that the minimum value for a correct header is 5."
			 */
			((packet->ip->ip_hl << 2) < (u_int8_t)sizeof(struct ip)) ||
			/* same applies to the Total Length Field, which includes 
			 * header and payload. Note, though, that we only require the
			 * main header, not the IP options */
			/* from the IP spec (RFC 791):
			 *   "Total Length is the length of the datagram, measured in octets,
			 *    including internet header and data." */
			(ntohs(packet->ip->ip_len) < sizeof(struct ip)) ||
			/* we need a full IP header (cut options are OK) */
			((packet->l2_hlen + sizeof(struct ip)) > ntohl(packet->frame.caplen)) )
		{
		packet->l3_proto = -1;
		packet->ip = NULL;
		packet->ip_opts = NULL;
		(void)pcap_get_l3(packet);
		return -1;
		}

	/* get IP header length */
	packet->l3_hlen = (packet->ip->ip_hl<<2);
	packet->l3_hlen = MIN(packet->l3_hlen, htonl(packet->frame.caplen) -
			packet->l2_hlen);
	packet->l3_hlen = MAX(packet->l3_hlen, 0);

	/* get IP options length */
	packet->ip_optlen = packet->l3_hlen - sizeof(struct ip);
	packet->ip_optlen = MIN(packet->ip_optlen, htonl(packet->frame.caplen) -
			packet->l2_hlen - (int)sizeof(struct ip));
	packet->ip_optlen = MAX(packet->ip_optlen, 0);
	if ( packet->ip_optlen == 0 )
		packet->ip_opts = NULL;

	/* get the actual l3_len in the packet */
	packet->l3_len = htonl(packet->frame.caplen) - packet->l2_hlen;
	packet->l3_len = MIN(packet->l3_len, ntohs(packet->ip->ip_len));

	/* check ip checksum validity */
	packet->ip_sum_valid = (packet->ip->ip_sum ==
			ip_checksum ((uint8_t *)(packet->ip))) ? 1 : 0;

	/*
	 * \note On IP fragments, the IP length field actually states the 
	 *       size of the fragment, not the size of the full packet. 
	 *       ("[When fragmenting] a long internet datagram [...] [into] 
	 *       two new internet datagrams [...] [the] first portion of the 
	 *       data is placed in the first new internet datagram, and the 
	 *       total length field is set to the length of the first 
	 *       datagram." [See RFC 791, Section 2.3, Page 8])
	 *
	 *       Note also that, for UDP packets, the full (unfragmented) 
	 *       packet length can be obtained out of the UDP length field
	 *       (which includes the IP header itself). There's not such
	 *       thing in TCP traffic.
	 */
	/* deal with IP offset fragments */
	if ( (ntohs(packet->ip->ip_off) & 0x1fff) != 0 )
		{
		/* this is a fragment, but not the first one: assume no L4 contents */
		packet->l4_len = 0;
		packet->l7_len = packet->l3_len - packet->l3_hlen;
		return 0;
		}

#if 0
			/* check for IP fragment MF */
			if ( (ntohs(packet->ip->ip_off) & 0x2000) != 0 )
				/* this is the first fragment: assume remaining data is IP length */
				packet->l3_len = htonl(packet->frame.caplen) - packet->l2_hlen;
#endif

	/* start assuming everything else is L4 */
	packet->l4_proto = (int)packet->ip->ip_p;
	packet->l4_len = packet->l3_len - packet->l3_hlen;

	return 0;
}



int pcap_get_ip6(packet_t *packet)
{
	/* point IPv6 header pointer */
	packet->ip6 = (struct ip6_hdr *)(packet->buffer + packet->l2_hlen);

	/* get IPv6 header length */
	packet->l3_hlen = sizeof(struct ip6_hdr);
	packet->l3_hlen = MIN(packet->l3_hlen, htonl(packet->frame.caplen) -
			packet->l2_hlen);
	packet->l3_hlen = MAX(packet->l3_hlen, 0);

	/* get the actual l3_len in the packet */
	packet->l3_len = htonl(packet->frame.caplen) - packet->l2_hlen;
	packet->l3_len = MIN(packet->l3_len, packet->l3_hlen +
			ntohs(packet->ip6->ip6_plen));

	/* start assuming everything else is L4 */
	packet->l4_proto = (int)packet->ip6->ip6_nxt;
	packet->l4_len = packet->l3_len - packet->l3_hlen;

	return 0;
}



int pcap_get_l4(packet_t *packet)
{
	/* point L4 header pointer */
	packet->l4 = packet->buffer + packet->l2_hlen + packet->l3_hlen;

	/* get the actual l4_len in the packet */
	packet->l4_len = packet->l3_len - packet->l3_hlen;

	/* unknown L4 header length */
	packet->l4_hlen = packet->l4_len;

	return 0;
}



int pcap_get_tcp (packet_t* packet)
{
	uint16_t tcp_sum;

	/* point TCP header pointers */
	packet->tcp = (struct tcphdr *)(packet->buffer + packet->l2_hlen +
			packet->l3_hlen);
	packet->tcp_opts = packet->buffer + packet->l2_hlen + packet->l3_hlen +
			sizeof(struct tcphdr);

	/* check we're happy with the TCP header */
	if (
			/* TCP headers should be at least 20-byte long */
			/* from the TCP spec (RFC 793):
			 *   "Data Offset:  4 bits
			 *
			 *      The number of 32 bit words in the TCP Header" */
			((packet->tcp->th_off << 2) < (u_int8_t)sizeof(struct tcphdr)) ||
			/* we need a full TCP header (cut options are OK) */
			((packet->l2_hlen + packet->l3_hlen + (u_int8_t)sizeof(struct tcphdr)) >
					ntohl(packet->frame.caplen)) )
		{
		packet->l4_proto = -1;
		packet->tcp = NULL;
		packet->tcp_opts = NULL;
		(void)pcap_get_l4(packet);
		return -1;
		}

	/* get TCP header length */
	packet->l4_hlen = packet->l3_len - packet->l3_hlen;
	packet->l4_hlen = MIN(packet->l4_hlen, htonl(packet->frame.caplen) -
			packet->l2_hlen - packet->l3_hlen);
	packet->l4_hlen = MIN(packet->l4_hlen, (uint32_t)packet->tcp->th_off<<2);
	packet->l4_hlen = MAX(packet->l4_hlen, 0);

	/* get TCP options length */
	packet->tcp_optlen = packet->l4_hlen - sizeof(struct tcphdr);
	packet->tcp_optlen = MIN(packet->tcp_optlen, htonl(packet->frame.caplen) -
			packet->l2_hlen - packet->l3_hlen - (int)sizeof(struct tcphdr));
	packet->tcp_optlen = MAX(packet->tcp_optlen, 0);
	if ( packet->tcp_optlen == 0 )
		packet->tcp_opts = NULL;

	/* get the actual l4_len in the packet */
	packet->l4_len = packet->l3_len - packet->l3_hlen;

	/* check tcp checksum validity */
	if ( packet->ip )
		tcp_sum = tcp_checksum((uint8_t *)(packet->ip));
	else if ( packet->ip6 )
		tcp_sum = tcp_checksum((uint8_t *)(packet->ip6));

	packet->tcp_sum_valid = (packet->tcp->th_sum == tcp_sum) ? 1 : 0;

	return 0;
}



int pcap_get_udp (packet_t* packet)
{
	/* point UDP header pointer */
	packet->udp = (struct udphdr *)(packet->buffer + packet->l2_hlen +
			packet->l3_hlen);

	/* get UDP header length */
	packet->l4_hlen = packet->l3_len - packet->l3_hlen;
	packet->l4_hlen = MIN(packet->l4_hlen, htonl(packet->frame.caplen) -
			packet->l2_hlen - packet->l3_hlen);
	packet->l4_hlen = MIN(packet->l4_hlen, sizeof(struct udphdr));
	packet->l4_hlen = MAX(packet->l4_hlen, 0);

	/* get the actual l4_len in the packet */
	packet->l4_len = packet->l3_len - packet->l3_hlen;

	return 0;
}



int pcap_get_icmp (packet_t* packet)
{
	/* point ICMP header pointer */
	packet->icmp = (struct icmphdr *)(packet->buffer + packet->l2_hlen +
			packet->l3_hlen);

	/* get ICMP header length */
	packet->l4_hlen = packet->l3_len - packet->l3_hlen;
	packet->l4_hlen = MIN(packet->l4_hlen, htonl(packet->frame.caplen) -
			packet->l2_hlen - packet->l3_hlen);
	packet->l4_hlen = MIN(packet->l4_hlen, sizeof(struct icmphdr));
	packet->l4_hlen = MAX(packet->l4_hlen, 0);

	/* get the actual l4_len in the packet */
	packet->l4_len = packet->l3_len - packet->l3_hlen;

	/* XXX ignore ICMP by now */
	txt_put_string(out_fp, "[%s NOT YET]\n", __func__);
	return 0;
}



int pcap_get_l7 (packet_t* packet)
{
	/* point L7 header pointer */
	packet->l7 = packet->buffer + packet->l2_hlen + packet->l3_hlen +
			packet->l4_hlen;

	/* get the actual l7_len in the packet */
	packet->l7_len = packet->l3_len - packet->l3_hlen - packet->l4_hlen;

	return 0;
}



int pcap_get_rem (packet_t* packet)
{
	/* get the actual rem_len in the packet */
	packet->rem_len = htonl(packet->frame.caplen) - packet->l2_hlen -
			packet->l3_len;

	/* point rem header pointer */
	if ( packet->rem_len == 0 )
		packet->rem = NULL;
	else
		packet->rem = packet->buffer + packet->l2_hlen + packet->l3_len;

	return 0;
}



/* text helper functions */

char *sprintf_string(string_t *str)
{
	static char buffer[1024];
	strncpy(buffer, str->s, str->l);
	buffer[str->l] = '\0';
	return buffer;
}



int getxvalue(char c)
{
	if ( isdigit(c) )
		return c - '0';
	else
		return (10 + tolower(c) - 'a');
}



int look_for_string(char **haystack, char *needle)
{
	int i;

	for (i=0; haystack[i] != NULL; ++i)
		if ( strcasecmp(haystack[i], needle) == 0 )
			break;

	if ( haystack[i] == NULL )
		return -1;

	return i;
}



#if !defined(HAVE_INET_NTOA)
/*
 * Convert network-format internet address
 * to base 256 d.d.d.d representation.
 */
char *inet_ntoa(struct in_addr in)
{
	static char b[18];
	register char *p;

	p = (char *)&in;
#define	UC(b)	(((int)b)&0xff)
	(void)snprintf(b, sizeof(b),
			"%u.%u.%u.%u", UC(p[0]), UC(p[1]), UC(p[2]), UC(p[3]));
	return (b);
}
#endif



char *addr_to_string (uint32_t addr)
{
	struct in_addr a;
	a.s_addr = addr; /* inet_ntoa wants network order */
	return inet_ntoa(a);
}



char* dump_ethaddr (uint8_t *addr)
{
	static char buffer[18];
	sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x",
			(int)*(addr), (int)*(addr+1), (int)*(addr+2),
			(int)*(addr+3), (int)*(addr+4), (int)*(addr+5));
	return buffer;
}




/**
 * \brief Encode a string
 * 
 * This function transforms a binary string into a readable one, where by
 * readable we mean every byte is substituted by "\xHH", where H represents
 * any hexadecimal digit
 * 
 * \param[in] pkt String
 * \param[in] len String length
 * \retval char Encoded string
 * \sa escape_string, unescape_string
 */
char *encode_string (unsigned char *pkt, int len)
{
	static char buf[MAX_PACKET_ASCII_LENGTH];
	int pi = 0;
	int bi = 0;

	for (pi=0; pi<len;++pi)
		bi += sprintf(buf+bi, "\\x%02x", pkt[pi]);

	/* terminate string */
	buf[bi++] = '\0';
	return buf;
}



/**
 * \brief Escape a string
 * 
 * This function transforms a binary string into a readable one, where by
 * readable we mean every byte is substituted by the most human-readable
 * possible form. In other words, this function works like encode_string(),
 * but being more human-friendly
 * 
 * \param[in] pkt String
 * \param[in] len String length
 * \retval char Encoded string
 * \sa escape_string, unescape_string
 */
char *escape_string (unsigned char *pkt, int len)
{
	static char buf[MAX_PACKET_ASCII_LENGTH];
	int pi = 0;
	int bi = 0;

	for (pi=0; pi<len;++pi)
		{
		switch (pkt[pi])
			{
			/* escape char (short) */
			case ' ': bi += sprintf(buf+bi, "\\ "); break; /* space */
			case '\0': bi += sprintf(buf+bi, "\\0"); break; /* null */
			case '\r': bi += sprintf(buf+bi, "\\r"); break; /* carriage return */
			case '\n': bi += sprintf(buf+bi, "\\n"); break; /* new line */
			case '\t': bi += sprintf(buf+bi, "\\t"); break; /* tab */
			case '\\': bi += sprintf(buf+bi, "\\\\"); break; /* escape char */
			default:
				/* escape non-printable and forbidden chars (long) */
				if ( (pkt[pi] < 32) || (pkt[pi] > 126) ||
						(pkt[pi] == SEP_FIELD) || (pkt[pi] == SEP_ENTRY) )
					/* escape char */
					bi += sprintf(buf+bi, "\\x%02x", pkt[pi]);
				else
					/* copy char */
					buf[bi++] = pkt[pi];
				}
		}

	/* terminate string */
	buf[bi++] = '\0';
	return buf;
}



int unescape_string_t (string_t *sin, char* buf, int buflen)
{
	return unescape_string (sin->s, sin->l, buf, buflen);
}



/**
 * \brief Unescape a string
 * 
 * This function undoes the substitution carried out by escape_string()
 * and encode_string()
 * 
 * \param[in] sin Input String
 * \param[in] sinlen Input String length
 * \param[out] buf Output String
 * \param[out] buflen Output String length
 * \retval int Error code (0 if OK, <0 if problems)
 * \sa escape_string, encode_string
 */
int unescape_string (char *sin, int sinlen, char* buf, int buflen)
{
	int si = 0;
	int bi = 0;

	for (si=0; sin[si]!='\0' && (sinlen == -1 || si<sinlen) && bi<buflen;)
		{
		if ( (sin[si] == '\\') && (sin[si+1] == ' ') && ++si && ++si )
			/* unescape char (short) */
			buf[bi++] = ' ';
		else if ( (sin[si] == '\\') && (sin[si+1] == '0') && ++si && ++si )
			/* unescape char (short) */
			buf[bi++] = '\0';
		else if ( (sin[si] == '\\') && (sin[si+1] == 'r') && ++si && ++si )
			/* unescape char (short) */
			buf[bi++] = '\r';
		else if ( (sin[si] == '\\') && (sin[si+1] == 'n') && ++si && ++si )
			/* unescape char (short) */
			buf[bi++] = '\n';
		else if ( (sin[si] == '\\') && (sin[si+1] == 't') && ++si && ++si )
			/* unescape char (short) */
			buf[bi++] = '\t';
		else if ( (sin[si] == '\\') && (sin[si+1] == '\\') && ++si && ++si )
			/* unescape char (short) */
			buf[bi++] = '\\';
		else if ( (sin[si] == '\\') && (sin[si+1] == 'x') &&
				(isxdigit(sin[si+2])) && (isxdigit(sin[si+3])) )
			{
			/* unescape char (long) */
			buf[bi] = (getxvalue(sin[si+2])<<4) + getxvalue(sin[si+3]);
			++bi;
			si += 4;
			}
		else if ( (sin[si] == ' ') || (sin[si] == '\t') || (sin[si] == '\n') ||
				(sin[si] == '\\') || (sin[si] < 32) || (sin[si] > 126) )
			/* skip ' ', \t, \n, '\\', and non-printable chars */
			++si;
		else
			/* copy char */
			buf[bi++] = sin[si++];
		}

	/* account for string */
	buf[MIN(bi,buflen-1)] = '\0';

	return bi;
}




/**
 * \brief Get a value from a string
 * 
 * \param[in] type Parameter type (TYPE_...)
 * \param[in] str Input string
 * \param[out] value Output value
 * \retval int Error code (0 if OK, <0 if problems, >0 if special)
 */
int getval_string (type_t type, char *str, void *value)
{
	switch (type)
		{
		case TYPE_STRING:
			{
			char **tmp = (char **)value;
			*tmp = str;
			return 0;
			break;
			}
		case TYPE_INT:
			return (sscanf(str, "%i", (int *)value) > 0) ? 0 : -1;
			break;
		case TYPE_INTEXT:
			if ( sscanf(str, "%i", (int *)value) > 0 )
				return 0;
			else if ( strncasecmp(KEYWORD_OK, str, strlen(KEYWORD_OK)) == 0 )
				{
				int *tmp = value;
				*tmp = VALUE_OK;
				return 1;
				}
			else
				return -1;
		case TYPE_UINT:
			if ( str[0] == '0' && tolower(str[1]) == 'x' )
				return (sscanf(str, "%x", (uint32_t *)value) > 0) ? 0 : -1;
			else if ( str[0] == '0' && tolower(str[1]) == 'x' )
				return (sscanf(str, "%o", (uint32_t *)value) > 0) ? 0 : -1;
			else
				return (sscanf(str, "%u", (uint32_t *)value) > 0) ? 0 : -1;
			break;
		case TYPE_UINTEXT:
			if ( str[0] == '0' && tolower(str[1]) == 'x' )
				return (sscanf(str, "%x", (uint32_t *)value) > 0) ? 0 : -1;
			else if ( str[0] == '0' && tolower(str[1]) == 'x' )
				return (sscanf(str, "%o", (uint32_t *)value) > 0) ? 0 : -1;
			else if ( sscanf(str, "%u", (uint32_t *)value) > 0 )
				return 0;
			else if ( strncasecmp(KEYWORD_OK, str, strlen(KEYWORD_OK)) == 0 )
				{
				int *tmp = value;
				*tmp = VALUE_OK;
				return 1;
				}
			else
				return -1;
		case TYPE_DOUBLE:
			return (sscanf(str, "%lf", (double *)value) > 0) ? 0 : -1;
			break;
		case TYPE_TWOUINTS:
			{
			char *dot;
			struct {
				uint32_t u1;
				uint32_t u2;
			} *tuvalue;
			/*(void *)tuvalue = value; */
			tuvalue = value;
			dot = index (str, '.');
			if ( dot == NULL )
				return -1;
			if ( snscanf(str, dot-str, "%u", &tuvalue->u1) <= 0 )
				return -1;
			if ( sscanf(dot+1, "%u", &tuvalue->u2) <= 0 )
				return -1;
			return 0;
			break;
			}
		case TYPE_ETHADDR:
			{
			struct ether_addr *tmp = ether_aton(str);
			if ( tmp == NULL )
				return -1;
 			memcpy(value, tmp, sizeof(struct ether_addr));
			return 0;
			break;
			}
		case TYPE_IPADDR:
			{
			struct in_addr tmp;
			if ( inet_aton(str, &tmp) == 0 )
				return -1;
 			memcpy(value, (void *)&tmp, sizeof(struct in_addr));
			return 0;
			break;
			}
		case TYPE_IPADDR6:
			{
			struct in6_addr tmp;
			if ( inet_pton(AF_INET6, str, &tmp) == 0 )
				return -1;
 			memcpy(value, (void *)&tmp, sizeof(struct in6_addr));
			return 0;
			break;
			}
		case TYPE_TCPFLAGS:
			{
			uint32_t flags = 0;
			int i = 0;
			while ( str[i] != '\0' )
				{
				switch (str[i])
					{
					case 'c': flags &= ~(1<<7); break;
					case 'C': flags |=   1<<7; break;
					case 'e': flags &= ~(1<<6); break;
					case 'E': flags |=   1<<6; break;
					case 'u': flags &= ~(1<<5); break;
					case 'U': flags |=   1<<5; break;
					case 'a': flags &= ~(1<<4); break;
					case 'A': flags |=   1<<4; break;
					case 'p': flags &= ~(1<<3); break;
					case 'P': flags |=   1<<3; break;
					case 'r': flags &= ~(1<<2); break;
					case 'R': flags |=   1<<2; break;
					case 's': flags &= ~(1<<1); break;
					case 'S': flags |=   1<<1; break;
					case 'f': flags &= ~(1<<0); break;
					case 'F': flags |=   1<<0; break;
					}
					++i;
				}
			*(uint32_t *)value = flags;
			return 0;
			break;
			}
		default:
			fprintf (stderr, "Error [%s]: Invalid or unimplemented type (%i)\n",
					__func__, type);
			exit(-1);
			break;
		}

	return -1;
}



/* text put functions */

int txt_put_packet(FILE *fp, packet_t* packet)
{
	/* dump frame info */
	txt_put_frame(fp, packet);

	/* dump L2 header */
	switch (ntohl(file_hdr.linktype))
		{
		case DLT_EN10MB:
			txt_put_ethernet(fp, packet);
			break;
		default:
			/* unknown structure datalink: won't try to interpret it */
			txt_put_l2(fp, packet);
			break;
		}

	/* dump l3 header */
	switch (packet->l3_proto)
		{
		case ETH_P_IP:
			txt_put_ip(fp, packet);
			break;

		case ETH_P_IPV6:
			txt_put_ip6(fp, packet);
			break;

		default:
			txt_put_l3(fp, packet);
			break;
		}

	if ( packet->l4_len > 0 )
		{
		/* dump L4 header */
		switch (packet->l4_proto)
			{
			case IPPROTO_TCP:
				txt_put_tcp(fp, packet);
				break;
			case IPPROTO_UDP:
				txt_put_udp(fp, packet);
				break;
#ifdef DONT_IGNORE_ICMP
			case IPPROTO_ICMP:
				txt_put_icmp(fp, packet);
				break;
#endif
			default:
				txt_put_l4(fp, packet);
				break;
			}
		}

	/* dump l7 header */
	if ( packet->l7_len > 0 )
		txt_put_l7(fp, packet);

	/* dump the remaining data */
	if ( packet->rem_len > 0 )
		txt_put_rem(fp, packet);

	txt_put_string(fp, "\n");

	if ( immediate_mode )
		fflush(fp);

	return 0;
}



int txt_put_file_header(FILE *fp, struct pcap_file_header *hdr)
{
	txt_put_string(fp, "%s%c %s, ", TEXT_GENERIC_HEADER, SEP_FIELD,
			TEXT_FORMAT_NAME);

	txt_put_string(fp, "%s%c %i, ", txt_label_file_header[0], SEP_FIELD,
			little_endian);
	txt_put_string(fp, "%s%c 0x%08x, ", txt_label_file_header[1], SEP_FIELD,
			ntohl(hdr->magic));
	txt_put_string(fp, "%s%c 0x%04x, ", txt_label_file_header[2], SEP_FIELD,
			ntohs(hdr->version_major));
	txt_put_string(fp, "%s%c 0x%04x, ", txt_label_file_header[3], SEP_FIELD,
			ntohs(hdr->version_minor));
	txt_put_string(fp, "%s%c 0x%08x, ", txt_label_file_header[4], SEP_FIELD,
			ntohl(hdr->thiszone));
	txt_put_string(fp, "%s%c 0x%08x, ", txt_label_file_header[5], SEP_FIELD,
			ntohl(hdr->sigfigs));
	txt_put_string(fp, "%s%c %i, ", txt_label_file_header[6], SEP_FIELD,
			ntohl(hdr->snaplen));
	txt_put_string(fp, "%s%c %i\n", txt_label_file_header[7], SEP_FIELD,
			ntohl(hdr->linktype));
	txt_put_string(fp, "\n");

	return 0;
}




/**
 * \brief Writes a text description of a pcap packet frame header
 * 
 * \param[in] fp File Pointer
 * \param[in] packet Packet
 * \retval int Error code (0 if OK, <0 if problems)
 * \sa pcap_postprocess_packet
 */
int txt_put_frame(FILE *fp, packet_t* packet)
{
	txt_put_string(fp, "%s%c packet, ", TEXT_GENERIC_HEADER, SEP_FIELD);

	/* packet index */
	txt_put_string(fp, "%s%c %i, ", txt_label_frame[0], SEP_FIELD,
			packet->index);
	/* timestamp */
	txt_put_string(fp, "%s%c %li.%06li, ", txt_label_frame[1], SEP_FIELD,
			ntohl(packet->frame.ts.tv_sec), ntohl(packet->frame.ts.tv_usec));
	/* caplen <> l2_hlen + l3_len + rem_len*/
	if ( packet->l2_hlen + packet->l3_len + packet->rem_len ==
			ntohl(packet->frame.caplen) )
		txt_put_string(fp, "%s%c %s (%i), ", txt_label_frame[2], SEP_FIELD,
				KEYWORD_OK, ntohl(packet->frame.caplen));
	else
		txt_put_string(fp, "%s%c %i, ", txt_label_frame[2], SEP_FIELD,
				ntohl(packet->frame.caplen));
	/* len <> l2_hlen + packet->ip->ip_len*/
	if ( packet->ip != NULL &&
			packet->l2_hlen + ntohs(packet->ip->ip_len) + packet->rem_len ==
					ntohl(packet->frame.len) )
		txt_put_string(fp, "%s%c %s (%i)\n", txt_label_frame[3], SEP_FIELD,
				KEYWORD_OK, ntohl(packet->frame.len));
	else
		txt_put_string(fp, "%s%c %i\n", txt_label_frame[3], SEP_FIELD,
				ntohl(packet->frame.len));

	return 0;
}



int txt_put_l2 (FILE *fp, packet_t* packet)
{
	txt_put_string(fp, "  %s%c l2, ", TEXT_GENERIC_HEADER, SEP_FIELD);
	txt_put_string(fp, "%s%c %s\n", txt_label_l2_header[0], SEP_FIELD,
			escape_string (packet->l2, packet->l2_hlen));

	return 0;
}



int txt_put_ethernet (FILE *fp, packet_t* packet)
{
	struct ether_header *eth = (struct ether_header *)packet->l2;

	txt_put_string(fp, "  %s%c ethernet, ", TEXT_GENERIC_HEADER, SEP_FIELD);

	txt_put_string(fp, "%s%c %s, ",     txt_label_ethernet_header[0], SEP_FIELD,
			dump_ethaddr(eth->ether_dhost));
	txt_put_string(fp, "%s%c %s, ",     txt_label_ethernet_header[1], SEP_FIELD,
			dump_ethaddr(eth->ether_shost));
	txt_put_string(fp, "%s%c 0x%04x\n", txt_label_ethernet_header[2], SEP_FIELD,
			ntohs(eth->ether_type));

	return 0;
}



int txt_put_l3 (FILE *fp, packet_t* packet)
{
	txt_put_string(fp, "  %s%c l3, ", TEXT_GENERIC_HEADER, SEP_FIELD);
	txt_put_string(fp, "%s%c %s\n", txt_label_l3_header[0], SEP_FIELD,
			escape_string (packet->l3, packet->l3_len));

	return 0;
}



int txt_put_ip (FILE *fp, packet_t* packet)
{
	txt_put_string(fp, "  %s%c ip, ", TEXT_GENERIC_HEADER, SEP_FIELD);

	txt_put_string(fp, "%s%c %i, ",     txt_label_ip_header[0], SEP_FIELD,
			packet->ip->ip_v);
	txt_put_string(fp, "%s%c %i, ",     txt_label_ip_header[1], SEP_FIELD,
			packet->ip->ip_hl);
	txt_put_string(fp, "%s%c 0x%02x, ", txt_label_ip_header[2], SEP_FIELD,
			packet->ip->ip_tos);
	if ( packet->l3_len == ntohs(packet->ip->ip_len) )
		/* packet->l3_len is right */
		txt_put_string(fp, "%s%c %s (%i), ",txt_label_ip_header[3], SEP_FIELD,
				KEYWORD_OK, ntohs(packet->ip->ip_len));
	else
		/* packet->l3_len is wrong */
		txt_put_string(fp, "%s%c %i, ",txt_label_ip_header[3], SEP_FIELD,
				ntohs(packet->ip->ip_len));
	txt_put_string(fp, "%s%c 0x%04x, ", txt_label_ip_header[4], SEP_FIELD,
			ntohs(packet->ip->ip_id));
	txt_put_string(fp, "%s%c %i, ",     txt_label_ip_header[5], SEP_FIELD,
			ntohs(packet->ip->ip_off)>>15);
	txt_put_string(fp, "%s%c %c, ",     txt_label_ip_header[6], SEP_FIELD,
			(((ntohs(packet->ip->ip_off)>>14)&0x1) != 0) ? '1' : '0');
	txt_put_string(fp, "%s%c %c, ",     txt_label_ip_header[7], SEP_FIELD,
			(((ntohs(packet->ip->ip_off)>>13)&0x1) != 0) ? '1' : '0');
	txt_put_string(fp, "%s%c +%i, ",    txt_label_ip_header[8], SEP_FIELD,
			ntohs(packet->ip->ip_off)&0x1fff);
	txt_put_string(fp, "%s%c %i, ",     txt_label_ip_header[9], SEP_FIELD,
			packet->ip->ip_ttl);
	txt_put_string(fp, "%s%c %i, ",     txt_label_ip_header[10], SEP_FIELD,
			packet->ip->ip_p);
	/* cksum */
	if ( packet->ip_sum_valid )
		txt_put_string(fp, "%s%c %s (0x%04x), ",txt_label_ip_header[11], SEP_FIELD,
				KEYWORD_OK, ntohs(packet->ip->ip_sum));
	else
		txt_put_string(fp, "%s%c 0x%04x, ", txt_label_ip_header[11], SEP_FIELD,
				ntohs(packet->ip->ip_sum));
	txt_put_string(fp, "%s%c %s, ",     txt_label_ip_header[12], SEP_FIELD,
			addr_to_string (packet->ip->ip_src.s_addr));
	txt_put_string(fp, "%s%c %s",       txt_label_ip_header[13], SEP_FIELD,
			addr_to_string (packet->ip->ip_dst.s_addr));

	if ( packet->ip_optlen > 0 )
		/* dump ip options */
		txt_put_string(fp, ", %s%c %s", txt_label_ip_header[14], SEP_FIELD,
				encode_string (packet->ip_opts, packet->ip_optlen));

	txt_put_string(fp, "\n");
	return 0;
}



int txt_put_ip6 (FILE *fp, packet_t* packet)
{
	char buf[INET6_ADDRSTRLEN];

	txt_put_string(fp, "  %s%c ip6, ", TEXT_GENERIC_HEADER, SEP_FIELD);

	txt_put_string(fp, "%s%c 0x%08x, ",     txt_label_ip6_header[0], SEP_FIELD,
			ntohl(packet->ip6->ip6_flow));
	if ( packet->l3_len == (sizeof(struct ip6_hdr)+ntohs(packet->ip6->ip6_plen)) )
		/* packet->l3_len is right */
		txt_put_string(fp, "%s%c %s (%i), ",txt_label_ip6_header[1], SEP_FIELD,
				KEYWORD_OK, ntohs(packet->ip6->ip6_plen));
	else
		/* packet->l3_len is wrong */
		txt_put_string(fp, "%s%c %i, ",txt_label_ip6_header[1], SEP_FIELD,
				ntohs(packet->ip6->ip6_plen));
	txt_put_string(fp, "%s%c %i, ",     txt_label_ip6_header[2], SEP_FIELD,
			packet->ip6->ip6_nxt);
	txt_put_string(fp, "%s%c %i, ",     txt_label_ip6_header[3], SEP_FIELD,
			packet->ip6->ip6_hops);

	/* src address */
	(void)inet_ntop(AF_INET6, (const void *)&(packet->ip6->ip6_src), buf, 
			INET6_ADDRSTRLEN);
	txt_put_string(fp, "%s%c %s, ",     txt_label_ip6_header[4], SEP_FIELD, buf);

	/* dst address */
	(void)inet_ntop(AF_INET6, (const void *)&(packet->ip6->ip6_dst), buf, 
			INET6_ADDRSTRLEN);
	txt_put_string(fp, "%s%c %s",     txt_label_ip6_header[5], SEP_FIELD, buf);

	txt_put_string(fp, "\n");
	return 0;
}



int txt_put_l4 (FILE *fp, packet_t* packet)
{
	txt_put_string(fp, "  %s%c l4, ", TEXT_GENERIC_HEADER, SEP_FIELD);
	txt_put_string(fp, "%s%c %s\n", txt_label_l4_header[0], SEP_FIELD,
			escape_string (packet->l4, packet->l4_len));

	return 0;
}



int txt_put_tcp (FILE *fp, packet_t* packet)
{
	uint32_t seq, ack;

	txt_put_string(fp, "  %s%c tcp, ", TEXT_GENERIC_HEADER, SEP_FIELD);

	txt_put_string(fp, "%s%c %i, ",           txt_label_tcp_header[0], SEP_FIELD,
			ntohs(packet->tcp->th_sport));
	txt_put_string(fp, "%s%c %i, ",           txt_label_tcp_header[1], SEP_FIELD,
			ntohs(packet->tcp->th_dport));

	/* check whether seq/ack are avoidable */
	seq = seq_check(packet, SEQ);
	if ( seq == ntohl(packet->tcp->th_seq) )
		txt_put_string(fp, "%s%c %s (0x%08x), ",txt_label_tcp_header[2], SEP_FIELD,
				KEYWORD_OK, ntohl(packet->tcp->th_seq));
	else
		txt_put_string(fp, "%s%c 0x%08x, ",     txt_label_tcp_header[2], SEP_FIELD,
				ntohl(packet->tcp->th_seq));
		/* valid value */

	ack = seq_check(packet, ACK);
	if ( ack == ntohl(packet->tcp->th_ack) )
		/* valid value */
		txt_put_string(fp, "%s%c %s (0x%08x), ",txt_label_tcp_header[3], SEP_FIELD,
				KEYWORD_OK, ntohl(packet->tcp->th_ack));
	else
		txt_put_string(fp, "%s%c 0x%08x, ",     txt_label_tcp_header[3], SEP_FIELD,
				ntohl(packet->tcp->th_ack));

	txt_put_string(fp, "%s%c %i, ",           txt_label_tcp_header[4], SEP_FIELD,
			packet->tcp->th_off);
	txt_put_string(fp, "%s%c %i, ",           txt_label_tcp_header[5], SEP_FIELD,
			packet->tcp->th_x2);
	txt_put_string(fp, "%s%c %c%c%c%c%c%c%c%c, ", txt_label_tcp_header[6], SEP_FIELD,
			(((packet->tcp->th_flags>>7)&0x1) != 0) ? 'C' : 'c',
			(((packet->tcp->th_flags>>6)&0x1) != 0) ? 'E' : 'e',
			(((packet->tcp->th_flags>>5)&0x1) != 0) ? 'U' : 'u',
			(((packet->tcp->th_flags>>4)&0x1) != 0) ? 'A' : 'a',
			(((packet->tcp->th_flags>>3)&0x1) != 0) ? 'P' : 'p',
			(((packet->tcp->th_flags>>2)&0x1) != 0) ? 'R' : 'r',
			(((packet->tcp->th_flags>>1)&0x1) != 0) ? 'S' : 's',
			(((packet->tcp->th_flags>>0)&0x1) != 0) ? 'F' : 'f');
	txt_put_string(fp, "%s%c %i, ",           txt_label_tcp_header[7], SEP_FIELD,
			ntohs(packet->tcp->th_win));
	if ( packet->tcp_sum_valid )
		txt_put_string(fp, "%s%c %s (0x%04x), ",txt_label_tcp_header[8], SEP_FIELD,
				KEYWORD_OK, ntohs(packet->tcp->th_sum));
	else
		txt_put_string(fp, "%s%c 0x%04x, ",     txt_label_tcp_header[8], SEP_FIELD,
				ntohs(packet->tcp->th_sum));
	txt_put_string(fp, "%s%c %i",             txt_label_tcp_header[9], SEP_FIELD,
			ntohs(packet->tcp->th_urp));

	if ( packet->tcp_optlen > 0 )
		/* dump tcp options */
		txt_put_string(fp, ", %s%c %s", txt_label_tcp_header[10], SEP_FIELD,
				encode_string (packet->tcp_opts, packet->tcp_optlen));

	txt_put_string(fp, "\n");
	return 0;
}



int txt_put_udp (FILE *fp, packet_t* packet)
{
	txt_put_string(fp, "  %s%c udp, ", TEXT_GENERIC_HEADER, SEP_FIELD);

	txt_put_string(fp, "%s%c %i, ", txt_label_udp_header[0], SEP_FIELD,
			ntohs(packet->udp->uh_sport));
	txt_put_string(fp, "%s%c %i, ", txt_label_udp_header[1], SEP_FIELD,
			ntohs(packet->udp->uh_dport));
	txt_put_string(fp, "%s%c %i, ", txt_label_udp_header[2], SEP_FIELD,
			ntohs(packet->udp->uh_ulen));
	txt_put_string(fp, "%s%c 0x%04x\n", txt_label_udp_header[3], SEP_FIELD,
			ntohs(packet->udp->uh_sum));

	return 0;
}



int txt_put_icmp (FILE *fp, packet_t* packet)
{
	/* not yet */
	txt_put_string(fp, "  %s%c icmp, ", TEXT_GENERIC_HEADER, SEP_FIELD);
	/* XXX ignore ICMP by now */
	txt_put_string(fp, "[%s NOT YET]\n", __func__);
	return 0;
}



int txt_put_l7 (FILE *fp, packet_t* packet)
{
	txt_put_string(fp, "  %s%c l7, ", TEXT_GENERIC_HEADER, SEP_FIELD);
	txt_put_string(fp, "%s%c %s\n", txt_label_l7_header[0], SEP_FIELD,
			escape_string (packet->l7, packet->l7_len));
	return 0;
}



int txt_put_rem (FILE *fp, packet_t* packet)
{
	txt_put_string(fp, "  %s%c rem, ", TEXT_GENERIC_HEADER, SEP_FIELD);
	txt_put_string(fp, "%s%c %s\n", txt_label_rem_header[0], SEP_FIELD,
			escape_string (packet->rem, packet->rem_len));
	return 0;
}



void txt_put_string (FILE *fp, char *str, ...)
{
	va_list ap;

	/* do write */
	va_start (ap, str);
	vfprintf (fp, str, ap);
	va_end(ap);

	return;
}



/* pcap put functions */
int pcap_put_file_header (FILE *fp, struct pcap_file_header *hdr)
{
	int len;

	if ( little_endian )
		{
		/* write this trace in little endian format */
		struct pcap_file_header hdr2;
		hdr2.magic = swapl(hdr->magic);
		hdr2.version_major = swaps(hdr->version_major);
		hdr2.version_minor = swaps(hdr->version_minor);
		hdr2.thiszone = swapl(hdr->thiszone);
		hdr2.sigfigs = swapl(hdr->sigfigs);
		hdr2.snaplen = swapl(hdr->snaplen);
		hdr2.linktype = swapl(hdr->linktype);
		hdr = &hdr2;
		}

	/* dump file info */
	len = sizeof(struct pcap_file_header);
	return do_fwrite (fp, (uint8_t *)hdr, len);
}



void pcap_put_packet(packet_t* packet, FILE *fp)
{
	char buffer[MAX_PACKET_LENGTH];
	int bi = 0;

	if ( !packet->valid )
		return;

	bi += pcap_put_frame(buffer+bi, packet);
	bi += pcap_put_l2(buffer+bi, packet);

	/* dump L3 header */
	switch (packet->l3_proto)
		{
		case ETH_P_IP:
			bi += pcap_put_ip(buffer+bi, packet);
			break;

		case ETH_P_IPV6:
			bi += pcap_put_ip6(buffer+bi, packet);
			break;

		default:
			bi += pcap_put_l3(buffer+bi, packet);
			break;
		}

	if ( packet->l4_hlen > 0 )
		{
		/* dump L4 header */
		switch (packet->l4_proto)
			{
			case IPPROTO_TCP:
				bi += pcap_put_tcp(buffer+bi, packet); break;
			case IPPROTO_UDP:
				bi += pcap_put_udp(buffer+bi, packet); break;
			case IPPROTO_ICMP:
#ifdef DONT_IGNORE_ICMP
				bi += pcap_put_icmp(buffer+bi, packet); break;
#endif
			default:
				bi += pcap_put_l4(buffer+bi, packet);
				break;
			}
		}

	bi += pcap_put_l7(buffer+bi, packet);
	bi += pcap_put_rem(buffer+bi, packet);

	/* packet postprocessing */
	pcap_postprocess_packet(buffer, packet);

	/* write the packet to the file descriptor */
	if ( do_fwrite (fp, (uint8_t *)buffer, bi) < 0 )
		{
		/* invalid write */
		fprintf (stderr, "Error [%s]: cannot write on fp (%s)\n",
				__func__, my_strerror(errno));
		exit(-1);
		}

	/* count the packet */
	++packet_counter;

	/* reset packet contents */
	packet_reset(packet);
}



/**
 * \brief Postprocess packet
 * 
 * Post-process a packet, fixing the ip/tcp checksums, the lengths, and 
 * the tcp seq/ack numbers
 * 
 * \param[in,out] buffer The buffer where the data is written
 * \param[in,out] packet The packet
 * \retval none
 */
void pcap_postprocess_packet(char *buffer, packet_t* packet)
{
	int fh_len = sizeof(struct pcaptxt_pkthdr);

	/* get actual (snaplen) l3_len */
	packet->l3_len = packet->l3_hlen + packet->l4_hlen + packet->l7_len;

	/* fix ip.ip_len */
	if ( packet->ip && ntohs(packet->ip->ip_len) == (uint16_t)VALUE_OK )
		{
		uint16_t *ptr = (uint16_t *)(buffer + fh_len + packet->l2_hlen + 2);
		packet->ip->ip_len = htons(packet->l3_len);
		*ptr = packet->ip->ip_len;
		}

	/* fix ip6.ip6_plen */
	if ( packet->ip6 && ntohs(packet->ip6->ip6_plen) == (uint16_t)VALUE_OK )
		{
		uint16_t *ptr = (uint16_t *)(buffer + fh_len + packet->l2_hlen + 4);
		packet->ip6->ip6_plen = htons(packet->l3_len - packet->l3_hlen);
		*ptr = packet->ip6->ip6_plen;
		}

	/* fix frame.caplen */
	if ( ntohl(packet->frame.caplen) == (uint32_t)VALUE_OK )
		{
		uint32_t *ptr = (uint32_t *)(buffer + 8);
		packet->frame.caplen = htonl(packet->l2_hlen + packet->l3_len +
				packet->rem_len);
		if ( little_endian )
			/* write this trace in little endian format */
			*ptr = swapl(packet->frame.caplen);
		else
			*ptr = packet->frame.caplen;
		}

	/* fix frame.len */
	if ( ntohl(packet->frame.len) == (uint32_t)VALUE_OK )
		{
		uint32_t *ptr = (uint32_t *)(buffer + 12);
		packet->frame.len = htonl(packet->l2_hlen + ntohs(packet->ip->ip_len) +
				packet->rem_len);
		if ( little_endian )
			/* write this trace in little endian format */
			*ptr = swapl(packet->frame.len);
		else
			*ptr = packet->frame.len;
		}

	/* fix/store tcp.th_seq */
	if (seq_table_enabled && packet->tcp && packet->l4_proto == IPPROTO_TCP)
		{
		uint32_t seq;
		uint32_t *ptr;

		seq = seq_check(packet, SEQ);
		if ( ntohl(packet->tcp->th_seq) == (uint32_t)VALUE_OK )
			{
			if ( seq == ntohl((uint32_t)VALUE_OK) )
				/* raise a warning */
				fprintf (stderr, "Error [%s]: couldn't resolve seq number\n", 
						__func__);
			ptr = (uint32_t *)(buffer + fh_len + packet->l2_hlen + packet->l3_hlen + 4);
			packet->tcp->th_seq = ntohl(seq);
			*ptr = packet->tcp->th_seq;
			}
		}

	/* fix tcp.th_ack */
	if (seq_table_enabled && packet->tcp && packet->l4_proto == IPPROTO_TCP)
		{
		uint32_t ack;
		uint32_t *ptr;

		ack = seq_check(packet, ACK);
		if ( ntohl(packet->tcp->th_ack) == (uint32_t)VALUE_OK )
			{
			if ( ack == ntohl((uint32_t)VALUE_OK) )
				/* raise a warning */
				fprintf (stderr, "Error [%s]: couldn't resolve ack number\n", 
						__func__);
			ptr = (uint32_t *)(buffer + fh_len + packet->l2_hlen + packet->l3_hlen + 8);
			packet->tcp->th_ack = ntohl(ack);
			*ptr = packet->tcp->th_ack;
			}
		}

	/* fix ip cksum */
	if ( packet->ip && packet->ip_sum_valid )
		{
		uint16_t *ptr = (uint16_t *)(buffer + fh_len + packet->l2_hlen + 10);
		packet->ip->ip_sum = ip_checksum ((uint8_t *)(packet->ip));
		*ptr = packet->ip->ip_sum;
		}

	/* fix tcp cksum */
	if ( packet->tcp && packet->tcp_sum_valid )
		{
		uint16_t *ptr = (uint16_t *)(buffer + fh_len + packet->l2_hlen +
				packet->l3_hlen + 16);
		packet->tcp->th_sum = tcp_checksum ((uint8_t *)(packet->ip));
		*ptr = packet->tcp->th_sum;
		}

	/* fix udp cksum */
	/* XXX should we? */

	return;
}



int pcap_put_frame (char *buf, packet_t *packet)
{
	struct pcaptxt_pkthdr *frame = &packet->frame;

	if ( little_endian )
		{
		/* write this trace in little endian format */
		struct pcaptxt_pkthdr frame2;
		frame2.len = swapl(frame->len);
		frame2.caplen = swapl(frame->caplen);
		frame2.ts.tv_sec = swapl(frame->ts.tv_sec);
		frame2.ts.tv_usec = swapl(frame->ts.tv_usec);
		frame = &frame2;
		}


	/* dump packet frame */
	memcpy(buf, (uint8_t *)frame, sizeof(struct pcaptxt_pkthdr));
	return sizeof(struct pcaptxt_pkthdr);
#if 0
	int len = sizeof(struct pcaptxt_pkthdr);
	return ( (fwrite ((uint8_t *)frame, 1, len, fp) == len) ? 0 : -1 );
	return do_fwrite (fp, (uint8_t *)frame, len);
#endif
}



int pcap_put_l2 (char *buf, packet_t *packet)
{
	if ( packet->l2_hlen > 0 )
		memcpy(buf, packet->l2, packet->l2_hlen);
	return packet->l2_hlen;
}



int pcap_put_l3 (char *buf, packet_t *packet)
{
	if ( packet->l3_hlen > 0 )
		memcpy(buf, packet->l3, packet->l3_hlen);
	return packet->l3_hlen;
}



int pcap_put_ip (char *buf, packet_t *packet)
{
	int len;

	/* check ip header */
	if ( packet->ip->ip_v != 4 )
		/* we only know how to process IPv4 */
		return 0;

	/* dump ip header */
	len = sizeof(struct ip);
	memcpy(buf, (uint8_t *)(packet->ip), len);

	/* dump ip options */
	if ( packet->ip_optlen > 0 )
		memcpy(buf+len, packet->ip_opts, packet->ip_optlen);

	return len + packet->ip_optlen;
}



int pcap_put_ip6 (char *buf, packet_t *packet)
{
	int len;

	/* check ip header */
	if ( ((ntohl(packet->ip6->ip6_flow) & 0xf0000000)>>28) != 6 )
		/* we only know how to process IPv6 */
		return 0;

	/* dump ip header */
	len = sizeof(struct ip6_hdr);
	memcpy(buf, (uint8_t *)(packet->ip6), len);

	return len;
}



int pcap_put_l4 (char *buf, packet_t *packet)
{
	if ( packet->l4_hlen > 0 )
		memcpy(buf, packet->l4, packet->l4_hlen);
	return packet->l4_hlen;
}



int pcap_put_tcp (char *buf, packet_t *packet)
{
	int len;

	/* dump tcp header */
	len = sizeof(struct tcphdr);
	memcpy(buf, (uint8_t *)(packet->tcp), len);

	/* dump tcp options */
	if ( packet->tcp_optlen > 0 )
		memcpy(buf+len, packet->tcp_opts, packet->tcp_optlen);

	return len + packet->tcp_optlen;
}



int pcap_put_udp (char *buf, packet_t *packet)
{
	/* dump udp header */
	memcpy(buf, (uint8_t *)(packet->udp), sizeof(struct udphdr));
	return sizeof(struct udphdr);
}



int pcap_put_icmp (char *buf, packet_t *packet)
{
	/* dump icmp header */
	memcpy(buf, (uint8_t *)(packet->icmp), sizeof(struct icmphdr));
	return sizeof(struct icmphdr);
}



int pcap_put_l7 (char *buf, packet_t *packet)
{
	/* dump L7 header */
	if ( packet->l7_len > 0 )
		memcpy(buf, packet->l7, packet->l7_len);
	return packet->l7_len;
}



int pcap_put_rem (char *buf, packet_t *packet)
{
	/* dump rem header */
	if ( packet->rem_len > 0 )
		memcpy(buf, packet->rem, packet->rem_len);
	return packet->rem_len;
}



/* text get functions */
int txt_get_change_state(int cur, char *buf, packet_t* packet)
{
	int next;

	/* get the new state */
	for (next=0;valid_states_s[next] != NULL;++next)
		if (strcasecmp(valid_states_s[next], buf) == 0 )
			/* got the state */
			break;

	if ( valid_states_s[next] == NULL )
		{
		/* invalid state */
		fprintf (stderr, "Error [%s]: invalid header string in line %i (%s)\n",
				__func__, line_number, buf);
		exit(-1);
		}

	if ( cur == HEADER_INIT && next != HEADER_FILE )
		{
		/* invalid first header */
		fprintf(stderr, "Error [%s]: invalid file format\n", __func__);
		exit(-1);
		}

	if ( cur == HEADER_FILE && next != HEADER_FILE )
		/* commit file header */
		pcap_put_file_header(out_fp, &file_hdr);

	if ( cur != HEADER_FILE && next == HEADER_FRAME )
		/* commit last modified packet */
		pcap_put_packet(packet, out_fp);

	/* check whether the new state is valid */
	if ( (cur == HEADER_INIT && next == HEADER_FILE) ||
			(cur != HEADER_INIT && next == HEADER_FRAME) ||
			(cur == HEADER_FRAME && next == HEADER_L2) ||
			(cur == HEADER_L2 && next == HEADER_L3) ||
			(cur == HEADER_L2 && next == HEADER_IP) ||
			(cur == HEADER_L2 && next == HEADER_IP6) ||
			(cur == HEADER_FRAME && next == HEADER_ETHERNET) ||
			(cur == HEADER_ETHERNET && next == HEADER_L3) ||
			(cur == HEADER_ETHERNET && next == HEADER_IP) ||
			(cur == HEADER_ETHERNET && next == HEADER_IP6) ||
			(cur == HEADER_IP && next == HEADER_L4) ||
			(cur == HEADER_IP && next == HEADER_TCP) ||
			(cur == HEADER_IP && next == HEADER_UDP) ||
			(cur == HEADER_IP && next == HEADER_ICMP) ||
			(cur == HEADER_IP6 && next == HEADER_L4) ||
			(cur == HEADER_IP6 && next == HEADER_TCP) ||
			(cur == HEADER_IP6 && next == HEADER_UDP) ||
			(cur == HEADER_IP6 && next == HEADER_ICMP) ||
			(cur != HEADER_INIT && next == HEADER_L7) ||
			(cur != HEADER_INIT && next == HEADER_REM) )
		/* good transition */
		(void)1;
	else
		{
		/* invalid transition */
		fprintf (stderr, "Error [%s]: invalid state transition in line %i (%s -> %s)\n",
				__func__, line_number, valid_states_s[cur], valid_states_s[next]);
		exit(-1);
		}

	return next;
}



int txt_get_pair(char *line, int state, string_t *left, string_t *right,
		string_t *rem)
{
	int i = 0;
	left->l = 0;
	right->l = 0;
	rem->l = 0;

	if ( state == TYPE_RIGHT )
		{
		/* if there's a single field sep. in the line, this is an inherited rem */
		if ( index(line, SEP_FIELD) != NULL )
			{
			rem->s = line;
			rem->l = strlen(line);
			return TYPE_FULL;
			}
		else
			/* otherwise skip left analysis */
			(void) 1;
		}
	else
		{
		left->s = line;

		/* left part is to the left of the field separator */
		while ( (line[i] != SEP_FIELD) && (line[i] != '\0') && (line[i] != '\n'))
			++i;
		left->l = i;

		if ( line[i] == '\0' || line[i] == '\n' )
			{
			/* end of line */
#ifdef DEBUG
			fprintf (debug_fs, "left: <nope>\n");
#endif
			return TYPE_LEFT;
			}

#ifdef DEBUG
		fprintf (debug_fs, "left: %s, ", sprintf_string(left));
#endif
		}

	if ( line[i] == SEP_FIELD )
		right->s = line+i+1;
	else
		/* no left part present */
		right->s = line;

	/* right part is to the left of the entry separator */
	while ( (line[i] != SEP_ENTRY) && (line[i] != '\0') && (line[i] != '\n'))
		++i;
	right->l = (line+i) - right->s;

	if ( line[i] == '\0' || line[i] == '\n' )
		{
		/* end of line */
#ifdef DEBUG
		fprintf (debug_fs, "right: <nope>\n");
#endif
		return TYPE_RIGHT;
		}

#ifdef DEBUG
	fprintf (debug_fs, "right: %s\n", sprintf_string(right));
#endif

	if ( line[i] == SEP_ENTRY )
		{
		rem->s = line+i+1;
		rem->l = strlen(rem->s);
		}
	else
		{
		rem->s = NULL;
		rem->l = 0;
		}

	return TYPE_FULL;
}



void txt_get_dispatch(string_t *left, string_t *right, packet_t* packet)
{
	char lbuf[MAX_PACKET_ASCII_LENGTH];
	char rbuf[MAX_PACKET_ASCII_LENGTH];
	int rlen;

	(void)unescape_string_t (left, lbuf, MAX_PACKET_ASCII_LENGTH);
	rlen = unescape_string_t (right, rbuf, MAX_PACKET_ASCII_LENGTH);

	if ( strcasecmp(TEXT_GENERIC_HEADER, lbuf) == 0 )
		cur = txt_get_change_state(cur, rbuf, packet);
	else
		switch (cur)
			{
			case HEADER_FILE:
				txt_get_file_header(lbuf, rbuf, &file_hdr);
				break;
			case HEADER_FRAME:
				txt_get_frame(lbuf, rbuf, packet);
				break;
			case HEADER_L2:
				txt_get_l2(lbuf, rbuf, rlen, packet);
				break;
			case HEADER_ETHERNET:
				txt_get_ethernet(lbuf, rbuf, packet);
				break;
			case HEADER_L3:
				txt_get_l3(lbuf, rbuf, rlen, packet);
				break;
			case HEADER_IP:
				txt_get_ip(lbuf, rbuf, rlen, packet);
				break;
			case HEADER_IP6:
				txt_get_ip6(lbuf, rbuf, rlen, packet);
				break;
			case HEADER_L4:
				txt_get_l4(lbuf, rbuf, rlen, packet);
				break;
			case HEADER_TCP:
				txt_get_tcp(lbuf, rbuf, rlen, packet);
				break;
			case HEADER_UDP:
				txt_get_udp(lbuf, rbuf, packet);
				break;
			case HEADER_ICMP:
				txt_get_icmp(lbuf, rbuf, packet);
				break;
			case HEADER_L7:
				txt_get_l7(lbuf, rbuf, rlen, packet);
				break;
			case HEADER_REM:
				txt_get_rem(lbuf, rbuf, rlen, packet);
				break;
			case HEADER_INIT:
			default:
				/* invalid state */
				fprintf (stderr, "Error [%s]: invalid state in line %i (%s)\n",
						__func__, line_number, valid_states_s[cur]);
				exit(-1);
			}

	return;
}



int txt_get_file_header(char *lbuf, char *rbuf, struct pcap_file_header *hdr)
{
	int id;
	uint32_t uvalue;

	if ( (id = look_for_string(txt_label_file_header, lbuf)) < 0 )
		{
		/* invalid label */
		fprintf (stderr, "Error [%s]: invalid label in line %i (%s)\n", __func__,
				line_number, lbuf);
		exit(-1);
		}

	/* get value */
	if ( getval_string (TYPE_UINT, rbuf, (void *)&uvalue) < 0 )
		{
		/* invalid state */
		fprintf (stderr, "Error [%s]: invalid %s value in line %i (%s)\n",
				__func__, txt_label_file_header[id], line_number, valid_states_s[cur]);
		exit(-1);
		}

#ifdef DEBUG
	fprintf (debug_fs, "%s: label \"%s\" has value 0x%08x\n", __func__, lbuf, uvalue);
#endif

	/* put value */
	switch (id)
		{
		case 0:
			little_endian = uvalue; break;
		case 1:
			hdr->magic = htonl(uvalue); break;
		case 2:
			hdr->version_major = htons((short)uvalue); break;
		case 3:
			hdr->version_minor = htons((short)uvalue); break;
		case 4:
			hdr->thiszone = htonl(uvalue); break;
		case 5:
			hdr->sigfigs = htonl(uvalue); break;
		case 6:
			hdr->snaplen = htonl(uvalue); break;
		case 7:
			hdr->linktype = htonl(uvalue); break;
		}

	return 0;
}



int txt_get_frame(char *lbuf, char *rbuf, packet_t *packet)
{
	int id;
	int res;
	uint32_t uvalue;
	struct {
		uint32_t u1;
		uint32_t u2;
	} tuvalue;

	if ( (id = look_for_string(txt_label_frame, lbuf)) < 0 )
		{
		/* invalid label */
		fprintf (stderr, "Error [%s]: invalid label in line %i (%s)\n", __func__,
				line_number, lbuf);
		exit(-1);
		}

	/* get value */
	switch (id)
		{
		case 1: /* time is a two-int */
			if ( getval_string (TYPE_TWOUINTS, rbuf, (void *)&tuvalue) < 0 )
				{
				/* invalid value */
				fprintf (stderr, "Error [%s]: invalid %s value in line %i (%s)\n",
						__func__, txt_label_frame[id], line_number,
						valid_states_s[cur]);
				exit(-1);
				}
#ifdef DEBUG
			fprintf (debug_fs, "%s: label \"%s\" has value %u.%u\n", __func__, lbuf, tuvalue.u1, tuvalue.u2);
#endif
			break;

		default:
			if ( (res = getval_string (TYPE_UINTEXT, rbuf, (void *)&uvalue)) < 0 )
				{
				/* invalid value */
				fprintf (stderr, "Error [%s]: invalid %s value in line %i (%s)\n",
						__func__, txt_label_frame[id], line_number,
						valid_states_s[cur]);
				exit(-1);
				}
#ifdef DEBUG
			fprintf (debug_fs, "%s: label \"%s\" has value 0x%08x\n", __func__, lbuf, uvalue);
#endif
			break;
		}

	/* put value */
	switch (id)
		{
		case 0:
#ifdef DEBUG
			fprintf (debug_fs, "%s: packet %i --------\n", __func__, uvalue);
#endif
			packet->index = htonl(uvalue); break;
		case 1:
				{
				packet->frame.ts.tv_sec = htonl(tuvalue.u1);
				packet->frame.ts.tv_usec = htonl(tuvalue.u2);
				break;
				}
		case 2:
			packet->frame.caplen = htonl(uvalue); break;
		case 3:
			packet->frame.len = htonl(uvalue); break;
		}

	/* mark the packet as valid */
	packet->valid = 1;

	return 0;
}




int txt_get_l2(char *lbuf, char *rbuf, int rlen, packet_t *packet)
{
	int id;
	uint32_t uvalue;
	char *svalue;

	/* point the l2 header, if necessary */
	if ( packet->l2 == NULL )
		packet->l2 = packet->buffer;

	if ( (id = look_for_string(txt_label_l2_header, lbuf)) < 0 )
		{
		/* invalid label */
		fprintf (stderr, "Error [%s]: invalid label in line %i (%s)\n",
				__func__, line_number, lbuf);
		exit(-1);
		}

	/* get value */
	(void)getval_string (TYPE_STRING, rbuf, (void *)&svalue);

	/* put value */
	switch (id)
		{
		case 0:
			memcpy((void *)packet->l2, (void *)svalue, rlen);
			packet->l2_hlen = rlen;
			break;
		}

	return 0;
}



int txt_get_ethernet(char *lbuf, char *rbuf, packet_t *packet)
{
	int id;
	struct ether_addr eavalue;
	uint32_t uvalue;
	struct ether_header *eth;

	/* point the l2 header, if necessary */
	if ( packet->l2 == NULL )
		{
		packet->l2 = packet->buffer;
		packet->l2_hlen = ETH_HLEN;
		}
	eth = (struct ether_header *)packet->l2;

	if ( (id = look_for_string(txt_label_ethernet_header, lbuf)) < 0 )
		{
		/* invalid label */
		fprintf (stderr, "Error [%s]: invalid label in line %i (%s)\n",
				__func__, line_number, lbuf);
		exit(-1);
		}

	/* get value */
	switch (id)
		{
		case 0: /* address is ETHADDR */
		case 1: /* address is ETHADDR */
			if ( getval_string (TYPE_ETHADDR, rbuf, (void *)&eavalue) < 0 )
				{
				/* invalid value */
				fprintf (stderr, "Error [%s]: invalid %s value in line %i (%s)\n",
						__func__, txt_label_ethernet_header[id], line_number,
						valid_states_s[cur]);
				exit(-1);
				}
#ifdef DEBUG
			fprintf (debug_fs, "%s: label \"%s\" has value %s\n", __func__, lbuf, ether_ntoa(&eavalue));
#endif
			break;

		default:
			if ( getval_string (TYPE_UINT, rbuf, (void *)&uvalue) < 0 )
				{
				/* invalid value */
				fprintf (stderr, "Error [%s]: invalid %s value in line %i (%s)\n",
						__func__, txt_label_ethernet_header[id], line_number,
						valid_states_s[cur]);
				exit(-1);
				}
#ifdef DEBUG
			fprintf (debug_fs, "%s: label \"%s\" has value 0x%08x\n", __func__, lbuf, uvalue);
#endif
			break;
		}

	/* put value */
	switch (id)
		{
		case 0:
			memcpy(eth->ether_dhost, (void *)&eavalue, sizeof(struct ether_addr)); break;
		case 1:
			memcpy(eth->ether_shost, (void *)&eavalue, sizeof(struct ether_addr)); break;
		case 2:
			eth->ether_type = htons((short)uvalue); break;
		}

	return 0;
}



int txt_get_l3(char *lbuf, char *rbuf, int rlen, packet_t *packet)
{
	int id;
	uint32_t uvalue;
	char *svalue;

	/* point the l3 header, if necessary */
	if ( packet->l3 == NULL )
		packet->l3 = packet->buffer + packet->l2_hlen;

	if ( (id = look_for_string(txt_label_l3_header, lbuf)) < 0 )
		{
		/* invalid label */
		fprintf (stderr, "Error [%s]: invalid label in line %i (%s)\n",
				__func__, line_number, lbuf);
		exit(-1);
		}

	/* get value */
	(void)getval_string (TYPE_STRING, rbuf, (void *)&svalue);

	/* put value */
	switch (id)
		{
		case 0:
			memcpy((void *)packet->l3, (void *)svalue, rlen);
			packet->l3_len = packet->l3_hlen = rlen;
			break;
		}

	return 0;
}



int txt_get_ip(char *lbuf, char *rbuf, int rlen, packet_t *packet)
{
	int id;
	int res;
	struct in_addr iavalue;
	char *svalue;
	uint32_t uvalue;

	/* point the l3 header, if necessary */
	if ( packet->ip == NULL )
		{
		packet->ip = (struct ip *)(packet->buffer + packet->l2_hlen);
		/* this is ip */
		/*  ZZZ there should be a better way to get l3_proto from the L2 header */
		packet->l3_proto = ETH_P_IP;
		/* IP length is at least this */
		packet->l3_hlen = sizeof(struct ip);
		}

	if ( (id = look_for_string(txt_label_ip_header, lbuf)) < 0 )
		{
		/* invalid label */
		fprintf (stderr, "Error [%s]: invalid label in line %i (%s)\n",
				__func__, line_number, lbuf);
		exit(-1);
		}

	/* get value */
	res = 0;
	switch (id)
		{
		case 12: /* address is IPADDR */
		case 13: /* address is IPADDR */
			if ( getval_string (TYPE_IPADDR, rbuf, (void *)&iavalue) < 0 )
				{
				/* invalid value */
				fprintf (stderr, "Error [%s]: invalid %s value in line %i (%s)\n",
						__func__, txt_label_ip_header[id], line_number,
						valid_states_s[cur]);
				exit(-1);
				}
#ifdef DEBUG
			fprintf (debug_fs, "%s: label \"%s\" has value %s\n", __func__, lbuf, inet_ntoa(iavalue));
#endif
			break;

		case 14: /* options is STRING */
			(void)getval_string (TYPE_STRING, rbuf, (void *)&svalue);
			break;

		default:
			if ( (res = getval_string (TYPE_UINTEXT, rbuf, (void *)&uvalue)) < 0 )
				{
				/* invalid value */
				fprintf (stderr, "Error [%s]: invalid %s value in line %i (%s)\n",
						__func__, txt_label_ip_header[id], line_number,
						valid_states_s[cur]);
				exit(-1);
				}
#ifdef DEBUG
			fprintf (debug_fs, "%s: label \"%s\" has value 0x%08x\n", __func__, lbuf, uvalue);
#endif
			break;
		}

	/* put value */
	switch (id)
		{
		case 0:
			packet->ip->ip_v = (uint8_t)uvalue; break;
		case 1:
			packet->ip->ip_hl = (uint8_t)uvalue;
			break;
		case 2:
			packet->ip->ip_tos = (uint8_t)uvalue; break;
		case 3:
			packet->ip->ip_len = htons((uint16_t)uvalue);
			break;
		case 4:
			packet->ip->ip_id = htons((uint16_t)uvalue); break;
		case 5:
			packet->ip->ip_off = uvalue<<15; break;
		case 6:
			packet->ip->ip_off |= uvalue<<14; break;
		case 7:
			packet->ip->ip_off |= uvalue<<13; break;
		case 8:
			packet->ip->ip_off = htons(packet->ip->ip_off | (((uint16_t)uvalue)&0x1fff)); break;
		case 9:
			packet->ip->ip_ttl = (uint8_t)uvalue; break;
		case 10:
			packet->ip->ip_p = (uint8_t)uvalue;
			packet->l4_proto = (int)packet->ip->ip_p;
			break;
		case 11:
			packet->ip->ip_sum = htons((uint16_t)uvalue);
			packet->ip_sum_valid = res;
			break;
		case 12:
			memcpy((void *)&(packet->ip->ip_src), (void *)&iavalue, sizeof(struct in_addr)); break;
		case 13:
			memcpy((void *)&(packet->ip->ip_dst), (void *)&iavalue, sizeof(struct in_addr)); break;
		case 14:
			packet->ip_opts = packet->buffer + packet->l2_hlen + sizeof(struct ip);
			memcpy((void *)packet->ip_opts, (void *)svalue, rlen);
			packet->ip_optlen = rlen;
			/* add options to the IP header length */
			packet->l3_hlen += packet->ip_optlen;
			break;
		}

	return 0;
}



int txt_get_ip6(char *lbuf, char *rbuf, int rlen, packet_t *packet)
{
	int id;
	int res;
	struct in6_addr iavalue;
	char *svalue;
	uint32_t uvalue;

	/* point the l3 header, if necessary */
	if ( packet->ip6 == NULL )
		{
		packet->ip6 = (struct ip6_hdr *)(packet->buffer + packet->l2_hlen);
		/* this is ipv6 */
		/*  ZZZ there should be a better way to get l3_proto from the L2 header */
		packet->l3_proto = ETH_P_IPV6;
		/* IP length is at least this */
		packet->l3_hlen = sizeof(struct ip6_hdr);
		}

	if ( (id = look_for_string(txt_label_ip6_header, lbuf)) < 0 )
		{
		/* invalid label */
		fprintf (stderr, "Error [%s]: invalid label in line %i (%s)\n",
				__func__, line_number, lbuf);
		exit(-1);
		}

	/* get value */
	res = 0;
	switch (id)
		{
		case 4: /* address is IPADDR6 */
		case 5: /* address is IPADDR6 */
			if ( getval_string (TYPE_IPADDR6, rbuf, (void *)&iavalue) < 0 )
				{
				/* invalid value */
				fprintf (stderr, "Error [%s]: invalid %s value in line %i (%s)\n",
						__func__, txt_label_ip6_header[id], line_number,
						valid_states_s[cur]);
				exit(-1);
				}
#ifdef DEBUG
			fprintf (debug_fs, "%s: label \"%s\" has value %s\n", __func__, lbuf, inet_ntoa(iavalue));
#endif
			break;

		default:
			if ( (res = getval_string (TYPE_UINTEXT, rbuf, (void *)&uvalue)) < 0 )
				{
				/* invalid value */
				fprintf (stderr, "Error [%s]: invalid %s value in line %i (%s)\n",
						__func__, txt_label_ip6_header[id], line_number,
						valid_states_s[cur]);
				exit(-1);
				}
#ifdef DEBUG
			fprintf (debug_fs, "%s: label \"%s\" has value 0x%08x\n", __func__, lbuf, uvalue);
#endif
			break;
		}

	/* put value */
	switch (id)
		{
		case 0:
			packet->ip6->ip6_flow = htonl((uint32_t)uvalue);
		case 1:
			packet->ip6->ip6_plen = htons((uint16_t)uvalue); break;
		case 2:
			packet->ip6->ip6_nxt = (uint8_t)uvalue;
			packet->l4_proto = (int)packet->ip6->ip6_nxt;
			break;
		case 3:
			packet->ip6->ip6_hops = (uint8_t)uvalue; break;
		case 4:
			memcpy((void *)&(packet->ip6->ip6_src), (void *)&iavalue, sizeof(struct in6_addr)); break;
		case 5:
			memcpy((void *)&(packet->ip6->ip6_dst), (void *)&iavalue, sizeof(struct in6_addr)); break;
		}

	return 0;
}



int txt_get_l4(char *lbuf, char *rbuf, int rlen, packet_t *packet)
{
	int id;
	uint32_t uvalue;
	char *svalue;

	/* point the l4 header, if necessary */
	if ( packet->l4 == NULL )
		packet->l4 = packet->buffer + packet->l2_hlen + packet->l3_hlen;

	if ( (id = look_for_string(txt_label_l4_header, lbuf)) < 0 )
		{
		/* invalid label */
		fprintf (stderr, "Error [%s]: invalid label in line %i (%s)\n",
				__func__, line_number, lbuf);
		exit(-1);
		}

	/* get value */
	(void)getval_string (TYPE_STRING, rbuf, (void *)&svalue);

	/* put value */
	packet->l4_proto = -1;
	switch (id)
		{
		case 0:
			memcpy((void *)packet->l4, (void *)svalue, rlen);
			packet->l4_len = packet->l4_hlen = rlen;
			break;
		}

	return 0;
}



int txt_get_tcp(char *lbuf, char *rbuf, int rlen, packet_t *packet)
{
	int id;
	int res;
	uint32_t uvalue;
	char *svalue;

	/* point the tcp header, if necessary */
	if ( packet->tcp == NULL )
		{
		packet->tcp = (struct tcphdr *)(packet->buffer + packet->l2_hlen +
				packet->l3_hlen);
		/* TCP length is at least this */
		packet->l4_hlen = sizeof(struct tcphdr);
		}

	if ( (id = look_for_string(txt_label_tcp_header, lbuf)) < 0 )
		{
		/* invalid label */
		fprintf (stderr, "Error [%s]: invalid label in line %i (%s)\n",
				__func__, line_number, lbuf);
		exit(-1);
		}

	/* get value */
	switch (id)
		{
		case 6: /* tcp flags */
			if ( getval_string (TYPE_TCPFLAGS, rbuf, (void *)&uvalue) < 0 )
				{
				/* invalid value */
				fprintf (stderr, "Error [%s]: invalid %s value in line %i (%s)\n",
						__func__, txt_label_tcp_header[id], line_number,
						valid_states_s[cur]);
				exit(-1);
				}
#ifdef DEBUG
			fprintf (debug_fs, "%s: label \"%s\" has value %i\n", __func__, lbuf, uvalue);
#endif
			break;

		case 10: /* options is STRING */
			(void)getval_string (TYPE_STRING, rbuf, (void *)&svalue);
			break;

		default:
			if ( (res = getval_string (TYPE_UINTEXT, rbuf, (void *)&uvalue)) < 0 )
				{
				/* invalid value */
				fprintf (stderr, "Error [%s]: invalid %s value in line %i (%s)\n",
						__func__, txt_label_tcp_header[id], line_number,
						valid_states_s[cur]);
				exit(-1);
				}
#ifdef DEBUG
			fprintf (debug_fs, "%s: label \"%s\" has value 0x%08x\n", __func__, lbuf, uvalue);
#endif
			break;
		}

	/* put value */
	packet->l4_proto = IPPROTO_TCP;
	switch (id)
		{
		case 0:
			packet->tcp->th_sport = htons((uint16_t)uvalue); break;
		case 1:
			packet->tcp->th_dport = htons((uint16_t)uvalue); break;
		case 2:
			packet->tcp->th_seq = htonl(uvalue); break;
		case 3:
			packet->tcp->th_ack = htonl(uvalue); break;
		case 4:
			packet->tcp->th_off = (uint8_t)uvalue;
			break;
		case 5:
			packet->tcp->th_x2 = (uint8_t)uvalue; break;
		case 6:
			packet->tcp->th_flags = (uint8_t)uvalue; break;
		case 7:
			packet->tcp->th_win = htons((uint16_t)uvalue); break;
		case 8:
			packet->tcp->th_sum = htons((uint16_t)uvalue);
			packet->tcp_sum_valid = res;
			break;
		case 9:
			packet->tcp->th_urp = htons((uint16_t)uvalue); break;
		case 10:
			packet->tcp_opts = packet->buffer + packet->l2_hlen + packet->l3_hlen +
					sizeof(struct tcphdr);
			memcpy((void *)packet->tcp_opts, (void *)svalue, rlen);
			packet->tcp_optlen = rlen;
			/* add options to the TCP header length */
			packet->l4_hlen += packet->tcp_optlen;
			break;
		}

	return 0;
}



int txt_get_udp(char *lbuf, char *rbuf, packet_t *packet)
{
	int id;
	int res;
	uint32_t uvalue;

	/* point the udp header, if necessary */
	if ( packet->udp == NULL )
		{
		packet->udp = (struct udphdr *)(packet->buffer + packet->l2_hlen +
				packet->l3_hlen);
		/* UDP length is exactly this */
		packet->l4_hlen = sizeof(struct udphdr);
		}

	if ( (id = look_for_string(txt_label_udp_header, lbuf)) < 0 )
		{
		/* invalid label */
		fprintf (stderr, "Error [%s]: invalid label in line %i (%s)\n",
				__func__, line_number, lbuf);
		exit(-1);
		}

	/* get value */
	if ( (res = getval_string (TYPE_UINTEXT, rbuf, (void *)&uvalue)) < 0 )
		{
		/* invalid state */
		fprintf (stderr, "Error [%s]: invalid %s value in line %i (%s)\n",
				__func__, txt_label_udp_header[id], line_number, valid_states_s[cur]);
		exit(-1);
		}

#ifdef DEBUG
	fprintf (debug_fs, "%s: label \"%s\" has value 0x%08x\n", __func__, lbuf, uvalue);
#endif

	/* put value */
	packet->l4_proto = IPPROTO_UDP;
	switch (id)
		{
		case 0:
			packet->udp->uh_sport = htons((uint16_t)uvalue); break;
		case 1:
			packet->udp->uh_dport = htons((uint16_t)uvalue); break;
		case 2:
			packet->udp->uh_ulen = htons((uint16_t)uvalue); break;
		case 3:
			packet->udp->uh_sum = htons((uint16_t)uvalue); break;
		}

	return 0;
}



int txt_get_icmp(char *lbuf, char *rbuf, packet_t *packet)
{
	/* point the icmp header, if necessary */
	packet->l4_proto = IPPROTO_ICMP;
	if ( packet->icmp == NULL )
		packet->icmp = (struct icmphdr *)(packet->buffer + packet->l2_hlen +
				packet->l3_hlen);

	return 0;
}



int txt_get_l7(char *lbuf, char *rbuf, int rlen, packet_t *packet)
{
	int id;
	char *svalue;

	/* point the l7 header, if necessary */
	if ( packet->l7 == NULL )
		packet->l7 = packet->buffer + packet->l2_hlen + packet->l3_hlen + 
				packet->l4_hlen;

	if ( (id = look_for_string(txt_label_l7_header, lbuf)) < 0 )
		{
		/* invalid label */
		fprintf (stderr, "Error [%s]: invalid label in line %i (%s)\n",
				__func__, line_number, lbuf);
		exit(-1);
		}

	/* get value */
	(void)getval_string (TYPE_STRING, rbuf, (void *)&svalue);

	/* put value */
	switch (id)
		{
		case 0:
			memcpy((void *)packet->l7, (void *)svalue, rlen);
			packet->l7_len = rlen;
			break;
		}

	return 0;
}



int txt_get_rem(char *lbuf, char *rbuf, int rlen, packet_t *packet)
{
	int id;
	char *svalue;

	/* point the l7 header, if necessary */
	if ( packet->rem == NULL )
		packet->rem = packet->buffer + packet->l2_hlen + packet->l3_hlen + 
				packet->l4_hlen + packet->l7_len;

	if ( (id = look_for_string(txt_label_rem_header, lbuf)) < 0 )
		{
		/* invalid label */
		fprintf (stderr, "Error [%s]: invalid label in line %i (%s)\n",
				__func__, line_number, lbuf);
		exit(-1);
		}

	/* get value */
	(void)getval_string (TYPE_STRING, rbuf, (void *)&svalue);

	/* put value */
	switch (id)
		{
		case 0:
			memcpy((void *)packet->rem, (void *)svalue, rlen);
			packet->rem_len = rlen;
			break;
		}

	return 0;
}



#if defined(__FreeBSD__)

/* the original pcap_open_live() doesn't open for writing
 * this is just copied from pcap-bpf.c:pcap_open_live()
 */

struct pcap_sf
{
	FILE *rfile;
	int swapped;
	int hdrsize;
	int version_major;
	int version_minor;
	uint8_t *base;
};
struct pcap_md
{
	struct pcap_stat stat;
	int use_bpf;
	u_long TotPkts;
	u_long TotAccepted;
	u_long TotDrops;
	long TotMissed;
	long OrigMissed;
};
struct pcap
{
	int fd;
	int snapshot;
	int linktype;
	int tzoff;
	int offset;
	struct pcap_sf sf;
	struct pcap_md md;
	int bufsize;
	uint8_t *buffer;
	uint8_t *bp;
	int cc;
	uint8_t *pkt;
	struct bpf_program fcode;
	char errbuf[PCAP_ERRBUF_SIZE];
};
#endif



/**
 * \brief Get IP checksum
 *
 *  Does not require caller to zero the cksum
 *
 * \param[in] ip_hdr IP header
 * \retval uint16_t Checksum in network order
 */
uint16_t ip_checksum(uint8_t *ip_hdr)
{
	uint32_t i;
	register uint32_t sum;
	uint16_t cksum;
	uint8_t ip_hlen;

	/* initialize sum */
	sum = 0;

	/* get IP header length */
	ip_hlen = ((*(ip_hdr)) & 0x0f)<<2;

	/* make 16 bit words out of every two adjacent bytes, and add them up */
	for (i = 0; i < ip_hlen; i = i + 2)
		if (i != 10)
			sum += (uint32_t)*(uint16_t *)(ip_hdr+i);

	/* take only 16 bits out of the 32 bit sum and add up the carries */
	while ((sum >> 16) != 0)
		sum = (sum & 0xffff) + (sum >> 16);

	/* one's complement the result */
	cksum = (uint16_t)(~sum & 0xffff);

	return cksum;
}



/**
 * \brief Get TCP checksum
 *
 * Does not require caller to zero the cksum
 *
 * \note This function operates in network order
 *
 * \param[in] ip_hdr IP header
 * \retval uint16_t Checksum in network order
 */
uint16_t tcp_checksum(uint8_t *ip_hdr)
{
	uint16_t i;
	register uint32_t sum;
	uint16_t cksum;
	uint8_t ip_v;
	uint16_t ip_hlen = 0;
  /* ip_len includes header and payload */
	uint16_t ip_len = 0;

	/* initialize sum */
	sum = 0;

	/* get IP header version */
	ip_v = ((*(ip_hdr)) & 0xf0)>>4;

	/* get IP header length and total length */
	if ( ip_v == 4 )
		{
		ip_hlen = ((*(ip_hdr)) & 0x0f)<<2;
		ip_len = ntohs(*(uint16_t *)(ip_hdr+2));
		}
	else if ( ip_v == 6 )
		{
		/* get IP header length */
		uint16_t ip_plen = 0;
		ip_plen = ntohs(*(uint16_t *)(ip_hdr+4));
		ip_hlen = sizeof(struct ip6_hdr);
		ip_len = ip_plen - ip_hlen;
		}

	/* add TCP pseudo header */
	if ( ip_v == 4 )
		{
		/* source address */
		sum += (uint32_t)*(uint16_t *)(ip_hdr+12);
		sum += (uint32_t)*(uint16_t *)(ip_hdr+14);
		/* destination address */
		sum += (uint32_t)*(uint16_t *)(ip_hdr+16);
		sum += (uint32_t)*(uint16_t *)(ip_hdr+18);
		/* IP protocol */
		sum += (uint32_t)(*(uint8_t *)(ip_hdr+9))<<8;
		/* TCP length */
		sum += (uint32_t)htons((ntohs(*(uint16_t *)(ip_hdr+2)) - ip_hlen));
		}
	else if ( ip_v == 6 )
		{
		/* src/dst address */
		for (i = 8; i < ip_hlen; i = i + 2)
			sum += (uint32_t)*(uint16_t *)(ip_hdr+i);

		/* payload length */
		sum += (uint32_t)*(uint16_t *)(ip_hdr+4);

		/* next header length */
		sum += (uint32_t)*(uint8_t *)(ip_hdr+6);
		}

	/* make 16 bit words out of every two adjacent TCP bytes, and add them up */
	for (i = ip_hlen; i < (ip_len-1); i = i + 2)
		if (i != (unsigned int)(ip_hlen + 16)) /* exclude TCP checksum */
			sum += (uint32_t)*(uint16_t *)(ip_hdr+i);

	if ( ip_len%2 == 1 )
		/* even length => add the last byte */
		sum += (uint32_t)((*(uint16_t *)(ip_hdr+i)) & htons(0xff00));

	/* take only 16 bits out of the 32 bit sum and add up the carries */
	while ((sum >> 16) != 0)
		sum = (sum & 0xffff) + (sum >> 16);

	/* one's complement the result */
	cksum = (uint16_t)(~sum & 0xffff);

	return cksum;
}





/* helper functions */

int do_fwrite(FILE *fp, uint8_t *buf, int len)
{
	int ret;

	if ( vim_mode )
		{
		/* store last two chars */
		if ( len > 0 ) last_char[0] = buf[len-1];
		if ( len > 1 ) last_char[1] = buf[len-2];
		}

	ret = ( ((int)fwrite (buf, 1, len, fp) == len) ? 0 : -1 );

	if ( immediate_mode )
		fflush(fp);

	return ret;
}



void string_append(string_t *str, string_t *post)
{
	if ( (str->l + post->l) > MAX_PACKET_ASCII_LENGTH )
		fprintf(stderr, "Error [%s]: String too big (%i)\n", __func__,
				MAX_PACKET_ASCII_LENGTH);
	memcpy(str->s+str->l, post->s, post->l);
	str->l += post->l;
	str->s[str->l] = '\0';
	return;
}



void string_reset(string_t *str)
{
	str->s[0] = '\0';
	str->l = 0;
}



/* substract struct timeval's */
struct timeval timeval_diff (struct timeval *ts2, struct timeval *ts1)
{
	struct timeval diff_ts;
	diff_ts.tv_sec = ts2->tv_sec - ts1->tv_sec;
	diff_ts.tv_usec = ts2->tv_usec - ts1->tv_usec;
	while ( diff_ts.tv_usec < 0 )
		{
		diff_ts.tv_sec -= 1;
		diff_ts.tv_usec += 1000000;
		}
	return diff_ts;
}



void packet_reset(packet_t *p)
{
	/* reset global packet contents */
	memset(p, 0, sizeof(packet_t));
	p->valid = 0;
}



/*
 * copied from /usr/include/bits/byteswap.h
 */
uint32_t swapl(uint32_t x)
{
	uint32_t out =
			((((x) & 0xff000000) >> 24) | (((x) & 0x00ff0000) >> 8) |
			(((x) & 0x0000ff00) << 8) | (((x) & 0x000000ff) << 24));
	return out;
}



uint16_t swaps(uint16_t x)
{
	uint32_t out =
			((((x) >> 8) & 0xff) | (((x) & 0xff) << 8));
	return out;

}



int seq_init(int len)
{
	uint32_t nbuckets;
	float max_bucket_occupancy_ratio;
	int copy_keys, copy_yields;


	/* init hash table */
	hf = hf_lcg_init();
	nbuckets = 1024;
	copy_keys = 1;
	copy_yields = 1;
	max_bucket_occupancy_ratio = DEFAULT_MAX_BUCKET_OCCUPANCY_RATIO;
	ht = ht_raw_init(HASH_OBJECT_TYPE_ONESIDED_CONNECTION,
			HASH_OBJECT_TYPE_UINT32,
			copy_keys, copy_yields, hf, nbuckets, max_bucket_occupancy_ratio);

	return 0;
}



void seq_fini()
{
	/* clean up the hash table */
	ht_raw_destroy(ht);
}





/**
 * \brief Checks whether a seq/ack number is coherent with the table. It also
 *        updates the new seq/ack
 * 
 * \param[in] packet Packet contents
 * \param[in] type SEQ or ACK
 * \retval uint32_t The seq/ack obtained from the table (VALUE_OK if not in
 *         table)
 */
uint32_t seq_check(packet_t* packet, int type)
{
	uint32_t result;
	conn_t conn;
	hash_table_item_t *item;
	uint32_t new;
	unsigned int ip_hlen, tcp_hlen;

	result = (uint32_t)VALUE_OK;

	/* ensure seq table is enabled */
	if ( seq_table_enabled == 0 )
		return result;

	/* ZZZ we don't support IPv6 seq tables (yet) */
	if ( packet->l3_proto == ETH_P_IPV6 )
		return result;

	/* build conn */
	conn.saddr = (type == SEQ) ? ntohl(packet->ip->ip_src.s_addr) :
			ntohl(packet->ip->ip_dst.s_addr);
	conn.sport = (type == SEQ) ? ntohs(packet->tcp->th_sport):
			ntohs(packet->tcp->th_dport);
	conn.daddr = (type == SEQ) ? ntohl(packet->ip->ip_dst.s_addr) :
			ntohl(packet->ip->ip_src.s_addr);
	conn.dport = (type == SEQ) ? ntohs(packet->tcp->th_dport):
			ntohs(packet->tcp->th_sport);
	conn.proto = packet->ip->ip_p;

	/* look up connection in the hash table */
	item = ht_raw_lookup(ht, (void*)&conn, NULL);
	if ( item != NULL )
		result = *(uint32_t *)item->yield;

	/* get new seq/ack value */
	if ( type == SEQ )
		{
		new = ntohl(packet->tcp->th_seq);
		if ( new == (uint32_t)VALUE_OK )
			/* OK value => use the older one */
			new = result;

		/* add the L4 contents length in the wire */
		ip_hlen = packet->ip->ip_hl<<2;
		tcp_hlen = packet->tcp->th_off<<2;
		new += (ntohs(packet->ip->ip_len) - ip_hlen - tcp_hlen);
		/* \note According to the TCP standard, both SYN and FIN flags occupy
		 * one sequence number. None of the other flags (URG, RST, PSH, ACK)
		 * occupy any space [RFC 793, Glossary]
		 */
		if ( ((packet->tcp->th_flags>>1)&0x1) != 0 ) /* SYN */
			++new;
		if ( ((packet->tcp->th_flags>>0)&0x1) != 0 ) /* FIN */
			++new;
		}
	else
		{
		new = ntohl(packet->tcp->th_ack);
		if ( new == (uint32_t)VALUE_OK )
			/* OK value => use the older one */
			new = result;
		}

	/* add new values to the table */
	if ( item != NULL )
		*(uint32_t *)item->yield = new;
	else
		(void)ht_raw_insert(ht, (void*)&conn, (void*)&new);

	return result;
}



/**
 * \brief Datalink to link header length calculator
 * 
 * \param[in] datalink Data link
 * \retval int Link Header Length (-1 if problems)
 */
int pcaptxt_get_linklen (int datalink)
{
	switch (datalink)
	{
		case DLT_RAW:
			/* raw IP (no link layer) */
			return 0;
			break;

		case DLT_NULL:
			/* FreeBSD localhost link layer size */
			/* XXX libpcap/savefile.c suggest 0 bytes here. Old code comes from Vern */
			return 4;
			break;

		case DLT_EN10MB:
			return ETH_HLEN;
			break;

		case DLT_FDDI:
			/* fddi_header + llc */
			return (13 + 8);
			break;

		case DLT_LINUX_SLL:
			/* linux cooked socket */
			return 16;
			break;

		default:
			return -1;
	}

	return 0;
}

