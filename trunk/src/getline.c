/* Copyright (C) 1994,1996-1998,2001,2003,2005 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.

   As a special exception, if you link the code in this file with
   files compiled with a GNU compiler to produce an executable,
   that does not cause the resulting executable to be covered by
   the GNU Lesser General Public License.  This exception does not
   however invalidate any other reasons why the executable file
   might be covered by the GNU Lesser General Public License.
   This exception applies to code released by its copyright holders
   in files containing the exception.  */


#include "config.h"


#include <stdio.h>
#ifdef __STDC__
#include <stdlib.h>
#endif
#include <string.h>
#include <errno.h>


#include "getline.h"



/**
 * \brief A portable line getter
 * 
 * \param[in] stream File descriptor
 * \param[in,out] pline Line
 * \param[in,out] len Line length
 * \retval int 1 if there is a line, 0 if run out of
 * \sa http://www.nersc.gov/~scottc/misc/docs/bro.1.0.3/fgetln_8c.html
 */
int my_getln (FILE *stream, char **pline, size_t *len)
{
	size_t sz = 0;
	char *buf, *lbuf;

#if defined(__linux__)
	lbuf = NULL;
	buf = NULL;
	sz = getline(&buf, &sz, stream);
#elif defined(__OpenBSD__) || defined(__FreeBSD__)
	buf = fgetln(stream, &sz);
	if ( buf != NULL )
		{
		if (buf[sz - 1] == '\n')
			buf[sz - 1] = '\0';
		else
			{
			/* EOF without EOL, copy and add the NUL */
			/* \note this leaks a line, which isn't a big deal */
			if ((lbuf = malloc(sz + 1)) == NULL)
				{
				fprintf(stderr, "Error: cannot allocate space of %d bytes\n", sz);
				exit(-1);
				}
			memcpy(lbuf, buf, sz);
			lbuf[sz] = '\0';
			buf = lbuf;
			}
		}
#endif

	if (pline)
		*pline = buf;

	if (len)
		*len = sz;

	return sz >= 0 ? 1 : 0;
}



#ifdef __linux__

/* Read up to (and including) a TERMINATOR from FP into *LINEPTR
   (and null-terminate it).  *LINEPTR is a pointer returned from malloc (or
   NULL), pointing to *N characters of space.  It is realloc'ed as
   necessary.  Returns the number of characters read (not including the
   null terminator), or -1 on error or EOF.  */

ssize_t my_getdelim(char **lineptr, size_t *n, int delimiter, FILE *fp)
{
	ssize_t result;
	ssize_t cur_len = 0;
	ssize_t len;

	if (lineptr == NULL || n == NULL) {
		return -1;
	}

	if (*lineptr == NULL || *n == 0) {
		*n = 120;
		*lineptr = (char *) malloc (*n);
		if (*lineptr == NULL) {
			result = -1;
			goto unlock_return;
		}
	}

	len = fp->_IO_read_end - fp->_IO_read_ptr;
	if (len <= 0) {
		if (__underflow (fp) == EOF) {
			result = -1;
			goto unlock_return;
		}
		len = fp->_IO_read_end - fp->_IO_read_ptr;
	}

	for (;;) {
		size_t needed;
		char *t;
		t = (char *) memchr ((void *) fp->_IO_read_ptr, delimiter, len);
		if (t != NULL)
			len = (t - fp->_IO_read_ptr) + 1;
		if (__builtin_expect (cur_len + len + 1 < 0, 0)) {
			result = -1;
			goto unlock_return;
		}
		/* Make enough space for len+1 (for final NUL) bytes. */
		needed = cur_len + len + 1;
		if (needed > *n) {
			char *new_lineptr;

			if (needed < 2 * *n)
				needed = 2 * *n;				/* Be generous. */
			new_lineptr = (char *) realloc (*lineptr, needed);
			if (new_lineptr == NULL) {
				result = -1;
				goto unlock_return;
			}
			*lineptr = new_lineptr;
			*n = needed;
		}
		memcpy (*lineptr + cur_len, (void *) fp->_IO_read_ptr, len);
		fp->_IO_read_ptr += len;
		cur_len += len;
		if (t != NULL || __underflow (fp) == EOF)
			break;
		len = fp->_IO_read_end - fp->_IO_read_ptr;
	}
	(*lineptr)[cur_len] = '\0';
	result = cur_len;

unlock_return:
	return result;
}



/* Like getdelim, but always looks for a newline. */
ssize_t getline (char **lineptr, size_t *n, FILE *stream)
{
	return my_getdelim (lineptr, n, '\n', stream);
}

#endif

