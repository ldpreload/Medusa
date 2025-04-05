#ifndef __LIBUTIL_H
#define __LIBUTIL_H

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include "syscalls.h"

static __inline__ int readfile(char *path, char *outbuf)
{
	struct stat sb;
	int fd, n;

	if (syscall(SYS_STAT, path, &sb))
		return 0;

 	fd = syscall(SYS_OPEN, path, O_RDONLY);
	if (fd < 0)
		return 0;
	n = syscall(SYS_READ, fd, outbuf, sb.st_size);
	syscall(SYS_CLOSE, fd);
	outbuf[sb.st_size] = 0;
	return 1;
}

char **get_str_list(int fd, int *nr_lines)
{
	char buf[1024];
	char *p1, *p2;
	char **strlist = malloc(64*sizeof(char *));
	int count = 0, n;

	n = syscall(SYS_READ, fd, buf, sizeof(buf)-1);
	buf[n] = 0;
	p1 = buf;
	while ((p2=strchr(p1, '\n'))) {
		*p2 = 0;
		strlist[count++] = strdup(p1);
		p1 = p2 + 1;
	}
	*nr_lines = count;
	return strlist;
}

#endif
