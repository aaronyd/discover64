#include "ping.h"

int
proc_v4(char *ptr, ssize_t len, struct timeval *tvrecv) {

    int hlen1, icmplen;
    double rtt;
    struct ip *ip;
    struct icmp *icmp;
    struct timeval *tvsend;
    char buf[NI_MAXHOST];

    ip = (struct ip *) ptr; /* start of IP header */
    hlen1 = ip->ip_hl << 2; /* length of IP header */

    icmp = (struct icmp *) (ptr + hlen1); /* start of ICMP header */
    if ((icmplen = len - hlen1) < 8)
        err_quit("[err] icmplen (%d) < 8", icmplen);

    getnameinfo(pr->sarecv, pr->salen, buf, NI_MAXHOST, NULL, 0, 0);

    if (icmp->icmp_type == ICMP_ECHOREPLY) {
        if (icmp->icmp_id != pid)
            return -1; /* not a response to our ECHO_REQUEST */
        if (icmplen < 16)
            err_quit("[err] icmplen (%d) < 16", icmplen);

        tvsend = (struct timeval *) icmp->icmp_data;
        tv_sub(tvrecv, tvsend);
        rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

        printf("[info] %d bytes from %s: seq=%u, ttl=%d, rtt=%.3f ms\n",
                icmplen, buf, htons(icmp->icmp_seq), ip->ip_ttl, rtt);
        return 0;
    } else if (verbose) {
        printf("[info] %d bytes from %s: type = %d, code = %d\n",
                icmplen, buf,
                icmp->icmp_type, icmp->icmp_code);
    }
    return 1;
}
