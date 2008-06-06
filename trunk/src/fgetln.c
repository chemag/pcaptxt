#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#include "getline.h"
#endif

int main(int argc, char **argv)
{
	FILE *fp;
	char *buf, *lbuf;
	size_t len;

	if ( argc < 2 )
		{
		printf ("Please provide a file to read\n");
		exit (-1);
		}

	fp = fopen(argv[1], "r");
	if ( fp == NULL )
		{
		perror("fopen");
		}

	lbuf = NULL;
	while ((buf = fgetln(fp, &len)))
		{
		if (buf[len - 1] == '\n')
			buf[len - 1] = '\0';
		else
			{
			/* EOF without EOL, copy and add the NUL */
			if ((lbuf = malloc(len + 1)) == NULL)
				err(1, NULL);
			memcpy(lbuf, buf, len);
			lbuf[len] = '\0';
			buf = lbuf;
			}
		printf("READ %i/%i bytes (%s)\n\n", len, strlen(buf), buf);
		}
	free(lbuf);

	fclose(fp);

	return;
}

