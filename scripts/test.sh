#!/bin/sh

DEBUG=0

PCAPBIN=../src/pcaptxt

test_trace () \
{
	local TRACE=$1
	local TMPTEXT=`mktemp /tmp/trace.txt.XXXXXX`
	local TMPTRACE=`mktemp /tmp/trace.pcap.XXXXXX`

	OUT=0
	ERROR=`$PCAPBIN -s p -r $TRACE -w $TMPTEXT 2>&1`
	if [ "$?" -ne "0" ]; then
		OUT=1
	fi
	if [ "$OUT" -eq "0" ]; then
		ERROR=`$PCAPBIN -s a -r $TMPTEXT -w $TMPTRACE 2>&1`
		if [ "$?" -ne "0" ]; then
			OUT=2
		fi
	fi
	if [ "$OUT" -eq "0" ]; then
		ERROR=`diff $TRACE $TMPTRACE 2>&1`
		if [ "$?" -ne "0" ]; then
			OUT=3
		fi
	fi
	# clean up
	\rm -f $TMPTEXT
	\rm -f $TMPTRACE
	return $OUT
}



usage() \
{
	echo "Usage: $0 [-d] [-h] trace"
}



parse_args() \
{
	SHIFT=0
	DEBUG=0
	OPTIND=1

	while [ $# -gt  $OPTIND ]
	do
		getopts "dh-:" flag "$@"
		case "$flag" in
			d)
				DEBUG=`expr $DEBUG + 1`
				;;
			h)
				usage
				exit 1
				;;
			-)
				case "$OPTARG" in
					debug)
						DEBUG=`expr $DEBUG + 1`
						;;
					help)
						usage
						exit 1
						;;
					*)
						continue
						;;
				esac
				;; 
			*)
				break
				;;
		esac
	done

	SHIFT=`expr $OPTIND - 1`
	return 0
}



###############################################


ARGC=$#
parse_args $@
if [ "$?" -ne "0" ]; then
	# error while parsing parameters
	exit 1
fi

# get rid of arguments
shift $SHIFT
ARGC=`expr $ARGC - $SHIFT`


i=0
while [ "$i" -lt "$ARGC" ]
do
	TRACE=$1
	# check whether this is a pcap trace
	FILEOUTPUT=`file $TRACE | grep tcpdump`
	if [ "x${FILEOUTPUT}" == "x" ]; then
		# this is no pcap trace
		if [ "${DEBUG}" -gt "0" ]; then
			echo "Testing $TRACE (not a tcpdump trace)"
		fi
	else
		# check trace is OK
		CHECK=`tcpdump -n -r $TRACE > /dev/null 2>&1`
		if [ "$?" -ne "0" ]; then
			if [ "${DEBUG}" -gt "0" ]; then
				echo "Testing $TRACE (trace is wrong, no more analysis)"
			fi
			shift
			i=`expr $i + 1`
			continue
		fi
		if [ "${DEBUG}" -gt "0" ]; then
			echo "Testing $TRACE"
		fi
		test_trace $TRACE
		if [ "$?" -ne "0" ]; then
			# pcap/diff returned something
			if [ "${DEBUG}" -le "0" ]; then
				echo "Testing $TRACE"
			fi
			echo "    ERROR: $ERROR"
		fi
	fi
	shift
	i=`expr $i + 1`
done



