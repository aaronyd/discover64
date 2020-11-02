#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>

#include <sys/types.h>
#include <sys/time.h>
#include <signal.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#define	BUFSIZE		    1500
#define MAXPACKETNUM    4
#define RESOLV          "/etc/resolv.conf"

/* globals */
char recvbuf[BUFSIZE];
char sendbuf[BUFSIZE];

int datalen; /* #bytes of data, following ICMP header */
char *host;
int nsent; /* add 1 for each sendto() */
int nrecv; /* add 1 for each icmp reply */
pid_t pid; /* our PID */
int sockfd;
int verbose;
int security; /* flag of dns security validation */

/* function prototypes */
int proc_v4(char *, ssize_t, struct timeval *);
int proc_v6(char *, ssize_t, struct timeval *);
void send_v4(void);
void send_v6(void);
void readloop(void);
void sig_alrm(int);
void tv_sub(struct timeval *, struct timeval *);
int check_heuristic(char* ip4_fqdn, char* dnskey);

struct proto {
    int (*fproc)(char *, ssize_t, struct timeval *);
    void (*fsend)(void);
    struct sockaddr *sasend; /* sockaddr{} for send, from getaddrinfo */
    struct sockaddr *sarecv; /* sockaddr{} for receiving */
    socklen_t salen; /* length of sockaddr{}s */
    int icmpproto; /* IPPROTO_xxx value for ICMP */
} *pr;

struct prefixs {
	int length;
	struct in6_addr* addr;
	struct prefixs *next;
};

struct prefixs *root;
struct prefixs *conductor;
