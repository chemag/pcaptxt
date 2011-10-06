" Name: pcap.vim
" Birthday: Mon Feb 26 14:55:31 PDT 2007
" Author: Jose M Gonzalez <chema@cs.berkeley.edu>
" Summary: Vim plugin for transparent editing of pcap trace files.
" TODO add some (sensible) highlighting syntax
" Section: Documentation {{{1
" Description:
"   
"   This script implements transparent editing of pcap tracefiles. The
"   The filename must have a ".pcap" suffix. When opening such a file
"   the content is transformed into text (using pcaptxt). The contents
"   are transformed back into a pcap trace format before writing.
"
" Installation: 
"
"   Copy the pcap.vim file to your $HOME/.vim/plugin directory.
"   Refer to ':help add-plugin', ':help add-global-plugin' and ':help
"   runtimepath' for more details about Vim plugins.
"
" Credits:
" Inspired on http://www.vi-improved.org/wiki/index.php/VimGpg

" Section: Plugin header {{{1
if (exists("loaded_pcap") || &cp || exists("#BufReadPre#*.pcap"))
	finish
endi
let loaded_pcap = 1

" Section: Autocmd setup {{{1
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

" Section: Highlight setup {{{1
" TODO(chema)

