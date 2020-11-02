#include "ping.h"

int
proc_v6(char *ptr, ssize_t len, struct timeval* tvrecv) {
    
    int icmp6len;
    double rtt;
    struct ip6_hdr *ip6;
    struct icmp6_hdr *icmp6;
    struct timeval *tvsend;
    char buf[NI_MAXHOST];

    icmp6 = (struct icmp6_hdr *) (ptr);
    icmp6len = len;
    
    if (icmp6len < 8)
        err_quit("[err] icmp6len (%d) < 8", icmp6len);

    getnameinfo(pr->sarecv, pr->salen, buf, NI_MAXHOST, NULL, 0, 0);

    if (icmp6->icmp6_type == ICMP6_ECHO_REPLY) {
        if (icmp6->icmp6_id != pid)
            return -1; /* not a response to our ECHO_REQUEST */
        if ( icmp6len < 16)
            err_quit("[err] icmp6len (%d) < 16", icmp6len);

        tvsend = (struct timeval *) (icmp6 + 1);
        tv_sub(tvrecv, tvsend);
        rtt = tvrecv->tv_sec * 1000.0 + tvrecv->tv_usec / 1000.0;

        printf("[info] %d bytes from %s: seq=%u, rtt=%.3f ms\n",
                icmp6len, buf, htons(icmp6->icmp6_seq), rtt);

        return 0;
    } else if (verbose) {
        printf("[info] %d bytes from %s: type = %d, code = %d id = %d\n",
                icmp6len, buf, icmp6->icmp6_type,
                icmp6->icmp6_code, icmp6->icmp6_id);
    }

    return 1;
}
