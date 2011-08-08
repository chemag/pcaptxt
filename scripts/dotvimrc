:set bg=dark
:set tabstop=2
:set shiftwidth=2
colorscheme adaryn
:set makeprg=make
syntax on
:set hlsearch

:if &term =~ "xterm"
:	if has("terminfo")
:		set t_Co=8
:		set t_Sf=[3%p1%dm
:		set t_Sb=[4%p1%dm
:	else
:		set t_Co=8
:		set t_Sf=[3%dm
:		set t_Sb=[4%dm
:	endif
:endif
" avoids bold colors
:set t_Co=16

" go back to the same line when opening a file that you were working on before
au BufReadPost * if line("'\"") > 0 && line("'\"") <= line("$") |
	\ exe "normal g'\"" | endif

" keep last edited line of files opened
set viminfo='20,\"50

" always show current line
set ruler

" Bro script
autocmd BufNewFile,BufRead *.bro set filetype=bro

" permits incremental search
:set incsearch

" tells vi to read an execute any .vimrc in the current directory (security breach!)
set exrc

" permits editing non-inserted text
" http://groups.google.com/groups?threadm=Pine.LNX.4.10.9904290905410.26153-100000%40riva.ucam.org&rnum=2&prev=/&frame=on
:set bs=2

" some useful key mappings
:map [1;5C W
:map [1;5D B


" Transparent editing of gpg encrypted files.
" By Wouter Hanegraaff <wouter@blub.net>
" http://www.vi-improved.org/wiki/index.php/VimGpg
augroup encrypted
	autocmd!
	" Ensure everybody knows this is gpg (i.e., no bin syntax)
	autocmd BufNewFile,BufRead          *.gpg set filetype=gpg
	" First make sure nothing is written to ~/.viminfo while editing
	" an encrypted file.
	autocmd BufReadPre,FileReadPre      *.gpg set viminfo=
	" We don't want a swap file, as it writes unencrypted data to disk
	autocmd BufReadPre,FileReadPre      *.gpg set noswapfile
	" Switch to binary mode to read the encrypted file
	autocmd BufReadPre,FileReadPre      *.gpg set bin
	autocmd BufReadPre,FileReadPre      *.gpg let shsave=&sh
	autocmd BufReadPre,FileReadPre      *.gpg let &sh='sh'
	autocmd BufReadPre,FileReadPre      *.gpg let ch_save = &ch|set ch=2
	"autocmd BufReadPost,FileReadPost    *.gpg '[,']!tee DEBUG
	autocmd BufReadPost,FileReadPost    *.gpg '[,']!gpg --decrypt --default-recipient-self 2> /dev/null
	autocmd BufReadPost,FileReadPost    *.gpg let &sh=shsave
	" Switch to normal mode for editing
	autocmd BufReadPost,FileReadPost    *.gpg set nobin
	autocmd BufReadPost,FileReadPost    *.gpg let &ch = ch_save|unlet ch_save
	autocmd BufReadPost,FileReadPost    *.gpg execute ":doautocmd BufReadPost " . expand("%:r")
	" Convert all text to encrypted text before writing
	autocmd BufWritePre,FileWritePre    *.gpg set bin
	autocmd BufWritePre,FileWritePre    *.gpg let shsave=&sh
	autocmd BufWritePre,FileWritePre    *.gpg let &sh='sh'
	autocmd BufWritePre,FileWritePre    *.gpg '[,']!gpg --encrypt --default-recipient-self 2>/dev/null
	autocmd BufWritePre,FileWritePre    *.gpg let &sh=shsave
	" Undo the encryption so we are back in the normal text, directly
	" after the file has been written.
	autocmd BufWritePost,FileWritePost  *.gpg silent u
	autocmd BufWritePost,FileWritePost  *.gpg set nobin
augroup END


" vim -b : edit non-gpg binaries using xxd-format!
if has("havenot")
"if has("autocmd")
	augroup Binary
		autocmd!
		autocmd BufReadPre  * if &filetype!='gpg'
		autocmd BufReadPre  *   .bin let &bin=1
		autocmd BufReadPre  * endif
		autocmd BufReadPost * if &filetype!='gpg'
		autocmd BufReadPost *   if &bin | %!xxd
		autocmd BufReadPost *     set syntax=xxdbin | set ft=xxdbin | endif
		autocmd BufReadPost *   endif
		autocmd BufReadPost * endif
		"autocmd BufWritePre *   if &bin | %!xxd -r
		"autocmd BufWritePre *   endif
		"autocmd BufWritePre * endif
	augroup END
endif



" Nice editing of pcap traces.
" Inspired on http://www.vi-improved.org/wiki/index.php/VimGpg
augroup pcaptrace
	autocmd!
	" Ensure everybody knows this is pcap (i.e., no bin syntax)
	autocmd BufNewFile,BufRead          *.pcap set filetype=pcap
	" First make sure nothing is written to ~/.viminfo while editing
	" an encrypted file.
	autocmd BufReadPre,FileReadPre      *.pcap set viminfo=
	" Switch to binary mode to read the trace
	autocmd BufReadPre,FileReadPre      *.pcap set bin
	autocmd BufReadPre,FileReadPre      *.pcap let shsave=&sh
	autocmd BufReadPre,FileReadPre      *.pcap let &sh='sh'
	autocmd BufReadPre,FileReadPre      *.pcap let ch_save = &ch|set ch=2
	"autocmd BufReadPost,FileReadPost    *.pcap '[,']!tee DEBUG
	autocmd BufReadPost,FileReadPost    *.pcap '[,']!pcaptxt -s p 2> /dev/null
	"autocmd BufReadPost,FileReadPost    *.pcap '[,']!pcaptxt -s p 2> /tmp/vimlog
	autocmd BufReadPost,FileReadPost    *.pcap let &sh=shsave
	" Switch to normal mode for editing
	autocmd BufReadPost,FileReadPost    *.pcap set nobin
	autocmd BufReadPost,FileReadPost    *.pcap let &ch = ch_save|unlet ch_save
	autocmd BufReadPost,FileReadPost    *.pcap execute ":doautocmd BufReadPost " . expand("%:r")
	" Convert all text to trace before writing
	autocmd BufWritePre,FileWritePre    *.pcap set bin
	autocmd BufWritePre,FileWritePre    *.pcap let shsave=&sh
	autocmd BufWritePre,FileWritePre    *.pcap let &sh='sh'
	" http://tech.groups.yahoo.com/group/vim/message/78100
	autocmd BufWritePre,FileWritePre    *.pcap set noendofline
	autocmd BufWritePre,FileWritePre    *.pcap '[,']!pcaptxt -V -s a 2>/dev/null
	"autocmd BufWritePre,FileWritePre    *.pcap '[,']!pcaptxt -V -s a 2>/tmp/vimlog
	autocmd BufWritePre,FileWritePre    *.pcap let &sh=shsave
	" Undo the ascii->pcap so we are back in the normal text, directly
	" after the file has been written.
	autocmd BufWritePost,FileWritePost  *.pcap silent u
	autocmd BufWritePost,FileWritePost  *.pcap set nobin
augroup END



""""""""""""
" BSD license comment block (in insert mode, type abreviation and then C-] or Esc)
iab BSDcb 
/* $Header: filename.c,v 1.1 2007/02/20 15:33:31 chema Exp $ 
 *
 * Copyright (c) 2007, Jose Maria Gonzalez (chema@cs.berkeley.edu)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the.
 *       distribution
 *     * Neither the name of the copyright holder nor the names of its 
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS ``AS 
 * IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED 
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A 
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
 * HOLDER AND CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED 
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR 
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF 
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING 
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

""""""""""""
" Ericsson copyright block
iab Ecb 
/***************************************************************
 Copyright (C) 2007 by Ericsson AB
* S - 125 26  STOCKHOLM
* SWEDEN, tel int + 46 8 719 0000
*
* The copyright to the computer program herein is the property of Ericsson 
* AB. The program may be used and/or copied only with the written permission 
* from Ericsson AB, or in accordance with the terms andconditions stipulated
* in the agreement/contract under which the program has been supplied.
*
* All rights reserved.
*/

""""""""""""
" File comment block (in insert mode, type abreviation and then C-] or Esc)
iab Fcb 
/**
 * \file filename.c
 *
 * \brief This file contains test module to test OLPC functions.
 *
 * \author  Jose M. Gonzalez
 * \date    2007-02-31
 * \version 0.01
 * \bug     None
 * \warning None
 */

""""""""""""
" function comment block (in insert mode, type fh and then C-] or Esc)
iab fcb 
/**
 * \brief Brief Description Here
 * 
 * Details here (optional) 
 * 
 * \param[in,out] name Description
 * \param[in] name Description
 * \retval type (None) Details here
 * \sa
 */


""""""""""""
" struct comment block (in insert mode, type fh and then C-] or Esc)
iab scb 
/**
 * \struct name
 * \brief Brief Description Here
 * 
 */
struct name {
	int member1;    /** Description of member1 */
	int member2;    /** Description of member2 */
}


" note: in order to use aspell with vim, check:
"   http://www.vim.org/scripts/script.php?script_id=465

" I normally write in English or Spanish
:if version < 700
:	"echo version
:else
:	set spelllang=en,es
:endif
:



