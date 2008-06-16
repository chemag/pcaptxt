#!/bin/sh
#
# Copyright (c) 2008, Jose Maria Gonzalez (chema@cs.berkeley.edu)
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the.
#       distribution
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived
#       from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS
# IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
# PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# HOLDER AND CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
# TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# $Id$


# pcadiff - a pcap trace format converter
#
# pcaptxt converts pcap traces to other useful trace formats
#
# usage is:
#      pcapdiff trace1 trace2
#
# interesting options will be written, some day

# ensure there are two arguments
argc=$#

if [ "${argc}" -ne "2" ]; then
	echo "Usage: pcapdiff trace1 trace2"
	exit
fi

trace1=$1
shift
trace2=$1
shift

# ensure both names are valid traces
if [ ! -r "$trace1" ]; then
	echo "Trace $trace1 non-readable"
fi

if [ ! -r "$trace2" ]; then
	echo "Trace $trace2 non-readable"
fi

# convert both traces to text
text1=`mktemp -t pcaptxt.XXXXXXXXXXX`
text2=`mktemp -t pcaptxt.XXXXXXXXXXX`
\rm -f $text1 $text2
pcaptxt -r $trace1 -s p -w $text1
pcaptxt -r $trace2 -s p -w $text2

# diff text version
diff $text1 $text2



