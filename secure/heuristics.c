#include "ping.h"

#include <stdlib.h>
#include <errno.h>
#include <resolv.h>
#include <unbound.h>  /* libunbound */

void get_prefix(const struct in6_addr* in, int len, struct in6_addr* out) {
    uint8_t m;
    int n;

    memset(out, 0, sizeof (struct in6_addr));

    n = 0;
    m = 0;

    while (len > 0) {
        m = in->s6_addr[n];

        if (len >= 8) {
            len -= 8;
        } else {
            m &= (0xff << (8 - len));
            len = 0;
        }
        out->s6_addr[n++] = m;
    }
}

int equal_prefix(const struct in6_addr* a, const struct in6_addr* b, int len) {
    uint8_t m;
    int n = 0;

    while (len > 0) {
        if (len >= 8) {
            m = 0xff;
        } else {
            m = 0xff << (8 - len);
        }
        if (((a->s6_addr[n] ^ b->s6_addr[n]) & m) == 0) {
            ++n;
            len -= 8;
        } else {
            return 0;
        }
    }
    return 1;
}

static int dns_query(char *name, char *dnskey) {
    /* Query DNS64 server for prefix. */

    extern int security;
    struct timeval start, end;
    double vtime;

    ns_msg handle;
    ns_rr rr;
    u_int16_t ct = 0;
    u_char ans[NS_PACKETSZ] = {0};
    int i;
    const u_char *cp;
    int ans_len = 0;
    int found = 0;

    if (!(_res.options & RES_INIT)) {
        res_init();
    }

    gettimeofday(&start, NULL);

    ans_len = res_search(name, ns_c_in, ns_t_aaaa, ans, NS_PACKETSZ);

    gettimeofday(&end, NULL); /* recording stop */
    tv_sub(&end, &start);
    vtime = end.tv_sec * 1000.0 + end.tv_usec / 1000.0;
    printf("[info] the first AAAA query time: %.4f ms\n", vtime);

    if (ans_len > 0) {
        if (ns_initparse(ans, ans_len, &handle) < 0) {
            return -1;
        }
    }

    /* Look for the AAAA answer.. */

    ct = ns_msg_count(handle, ns_s_an);

    /* store every different prefix in the linked list */
    for (i = 0; i < ct; i++) {
        if (ns_parserr(&handle, ns_s_an, i, &rr) == 0) {
            if ((ns_rr_type(rr) == ns_t_aaaa) && (ns_rr_rdlen(rr) == 16)) {
                /* Found the synthesized address, copy it. */
                cp = ns_rr_rdata(rr);
                
                if (security == 1) { /* need to validate */
                    printf("[info] validating address...\n");
                    
                    /* PTR check */
                    if (ptr_checking(cp)) {
                        err_quit("[err] invalid DNS response for the fqdn");
                    }
 
                    /* DNSSEC */
                    if (dnssec_validate(name, dnskey)) { 
                        err_quit("[err] inscure DNS response for the fqdn");
                    }
                }

                if ((find_pref64(cp, name)) == 1) { // find a new prefix
                    found++;
                }
            }
        }
    }

    return found;
}

/*
Usage:  check whether the ipv6 address can be trusted
        1) send PTR query
        2) compare domains to a tructed domain list
        3) aaaa query again for the new domain, and compare the
           ipv6 address
Return: 0 -- validation succeeds
        1 -- validation fails, the previous ip we get is invalid
*/
int ptr_checking(struct in6_addr* in6)
{
    int i, flag, result, status;
    // struct hostent *domain;
    char hbuf[1024];
    struct sockaddr_in6 ip6addr;
    struct addrinfo hints, *res, *rp;
    struct timeval start, end;
    double vtime;

    ip6addr.sin6_family = AF_INET6;
    ip6addr.sin6_addr = *in6;

    // send PTR query
    gettimeofday(&start, NULL); /* record running time */
    // domain = gethostbyaddr(in6, sizeof(struct in6_addr), AF_INET6);
    if (getnameinfo((struct sockaddr *)&ip6addr, sizeof(ip6addr), hbuf, 
            sizeof(hbuf), NULL, 0, NI_NAMEREQD)) {
        fprintf(stderr, "[err] ptr_checking -- could not resolve hostname\n");
        return 1;
    }

    printf("[debug] %s\n", hbuf);
 
    gettimeofday(&end, NULL); /* recording stop */
    tv_sub(&end, &start);
    vtime = end.tv_sec * 1000.0 + end.tv_usec / 1000.0;
    printf("[info] time: %.4f ms, ", vtime);

    // check trusted domain list, not implelmented now
    // do we need to check CNAME???

    // query for the hostname from PTR response
    gettimeofday(&start, NULL);
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET6;
    status = getaddrinfo(hbuf, NULL, &hints, &res);
    if (status != 0) {
        if (verbose) {
            fprintf(stderr, "[err] getaddrinfo: %s\n", gai_strerror(status));
        }
        err_sys("[err] domain validation -- fail to get ip addr");
    }

    // compare addresses to those previousely learned
    for (rp = res; rp != NULL; rp = rp->ai_next) {
        flag = 0;
        for (i = 0; i < 16; i++) {
            if (in6->s6_addr[i] != (&((struct sockaddr_in6*)
                    (rp->ai_addr))->sin6_addr)->s6_addr[i]) {
                flag = 1;
                break;
            }
        }

        if (flag == 0) {
            result = 0;
            break;
        } else {
            result = 1;
            continue;
        }
    }

    gettimeofday(&end, NULL); /* recording stop */
    tv_sub(&end, &start);
    vtime = end.tv_sec * 1000.0 + end.tv_usec / 1000.0;
    printf("%.4f ms, ", vtime);

    return result;
}

/*
Usage:  dnssec validation by using libunbound
Return: 0 -- security
        other -- insecurity
*/
int dnssec_validate(char *name, char *dnskey)
{
    struct ub_ctx* ctx;
    struct ub_result* result; 
    struct timeval start, end;
    double vtime;
    int retval;
    int flag;

    /* create context */
    ctx = ub_ctx_create();
    if(!ctx) {
        err_quit("[err] could not create unbound context");
    }

    /* read /etc/resolv.conf for DNS proxy settings */
    if( (retval = ub_ctx_resolvconf(ctx, RESOLV)) != 0) {
        if (verbose) {
            printf("[err] reading resolv.conf: %s. errno says: %s\n", 
                ub_strerror(retval), strerror(errno));
        }
        err_quit("[err] parsing resolv.conf error");
    }

    /* read /etc/hosts for locally supplied host addresses */
    if( (retval = ub_ctx_hosts(ctx, "/etc/hosts")) != 0) {
        if (verbose) {
            printf("[err] reading hosts: %s. errno says: %s\n", 
                ub_strerror(retval), strerror(errno));
        }
        err_quit("[err] parsing hosts file error");
    }

    /* read public keys for DNSSEC verification */
    if( (retval = ub_ctx_add_ta_file(ctx, dnskey)) != 0) {
        if (verbose) {
            printf("[err] adding keys: %s\n", ub_strerror(retval));
        }
        err_quit("[err] fail to use the dnssec keys");
    }

    
    gettimeofday(&start, NULL); /* recording stop */

    /* query for webserver */
    retval = ub_resolve(ctx, name, 
        28 /* TYPE AAAA */, 
        // 1, /* TYPE A */
        1 /* CLASS IN (internet) */, &result);
    if(retval != 0) {
        if (verbose) {
            printf("[err] resolve error: %s\n", ub_strerror(retval));
        }
        err_quit("[err] dnssec resolve error");
    }

    /* show security status */
    if(result->secure)
        flag = 0;
    else if(result->bogus)
        flag = 1;
    else
        flag = -1;

        
    gettimeofday(&end, NULL); /* recording stop */
    tv_sub(&end, &start);
    vtime = end.tv_sec * 1000.0 + end.tv_usec / 1000.0;
    printf("%.4f ms\n", vtime);

    ub_resolve_free(result);
    ub_ctx_delete(ctx);
    return flag;
}

int find_pref64( struct in6_addr* in6, /* Possibly synthesized address */                   
                        char* ip4_fqdn) /* IP address we are looking for.*/
{
    char buf[NI_MAXHOST];
    int i, length, addrnum;
    int flag = 0;
    int new_pref = 0;
    int m = 0;
    struct addrinfo hins, *rs, *rp;
    struct prefixs *headp;
    u_char* tmp = malloc(4);
    
    memset(&hins, 0, sizeof (hins));
    hins.ai_family = AF_INET;
    hins.ai_socktype = SOCK_STREAM;

    getaddrinfo(ip4_fqdn, NULL, &hins, &rs);

    /* we know this address was synthesized

       Synthesized addresses are of prefix length & format.. RFC6052

       +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
       |PL| 0-------------32--40--48--56--64--72--80--88--96--104---------|
       +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
       |32|     prefix    |v4(32)         | u | suffix                    |
       +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
       |40|     prefix        |v4(24)     | u |(8)| suffix                |
       +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
       |48|     prefix            |v4(16) | u | (16)  | suffix            |
       +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
       |56|     prefix                |(8)| u |  v4(24)   | suffix        |
       +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
       |64|     prefix                    | u |   v4(32)      | suffix    |
       +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
       |96|     prefix                                    |    v4(32)     |
       +--+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+ 

     */

     /*
     * Look for the fqdn within the synthesized address.
     * RFC draft says that if an IP is multiple time we need
     * discard the result and search again with another well-known IPv4 address.
     */
    
    for (rp = rs; rp != NULL; rp = rp->ai_next) { 
        if ((*(const __uint32_t *)(const void *)&in6->s6_addr[12]) ==
            *(const __uint32_t *)(const void *)&((struct sockaddr_in *)rp->ai_addr)->sin_addr) {
            if (m == 0) {
                flag = 1;
                length = 96;
                addrnum = 12;
            }
            m++;
        }

        if ((*(const __uint32_t *)(const void *)&in6->s6_addr[9]) ==
            *(const __uint32_t *)(const void *)&((struct sockaddr_in *)rp->ai_addr)->sin_addr) {
            if (m == 0) {
                flag = 1;
                length = 64;
                addrnum = 7;
            }
            m++;
        }

        memcpy(tmp, ((const __uint32_t *)(const void *)&in6->s6_addr[7]), 1);
        memcpy(tmp+1, ((const __uint32_t *)(const void *)&in6->s6_addr[9]), 3);
        if ((*(const __uint32_t *)(const void *) tmp) == 
            *(const __uint32_t *)(const void *)&((struct sockaddr_in *)rp->ai_addr)->sin_addr) {
            if (m == 0) {
                flag = 1;
                length = 56;
                addrnum = 6;
            }
            m++;
        }

        memcpy(tmp, ((const __uint32_t *)(const void *)&in6->s6_addr[6]), 2);
        memcpy(tmp+1, ((const __uint32_t *)(const void *)&in6->s6_addr[9]), 2);
        if ((*(const __uint32_t *)(const void *) tmp) == 
            *(const __uint32_t *)(const void *)&((struct sockaddr_in *)rp->ai_addr)->sin_addr) {
            if (m == 0) {
                flag = 1;
                length = 48;
                addrnum = 5;
            }
            m++;
        }

        memcpy(tmp, ((const __uint32_t *)(const void *)&in6->s6_addr[5]), 3);
        memcpy(tmp+1, ((const __uint32_t *)(const void *)&in6->s6_addr[9]), 1);
        if ((*(const __uint32_t *)(const void *) tmp) == 
            *(const __uint32_t *)(const void *)&((struct sockaddr_in *)rp->ai_addr)->sin_addr) {
            if (m == 0) {
                flag = 1;
                length = 40;
                addrnum = 4;
            }
            m++;
        }

        if ((*(const __uint32_t *)(const void *)&in6->s6_addr[4]) ==
            *(const __uint32_t *)(const void *)&((struct sockaddr_in *)rp->ai_addr)->sin_addr) {
            if (m == 0) {
                flag = 1;
                length = 32;
                addrnum = 3;
            }
            m++;
        }
    }

    // add the prefix to the linked list if it is new
    if (flag == 1 && !(is_duplicated_prefix(in6, length, addrnum))) {
        if ((conductor->next = malloc(sizeof(struct prefixs))) == NULL) {
            err_sys("[fatal] malloc -- out of memory");
        }
        conductor = conductor->next;
        conductor->next = NULL;
        
        if ((conductor->addr = malloc(sizeof(struct in6_addr))) == NULL) {
            err_sys("[fatal] malloc -- out of memory");
        }
        memset(&conductor->addr->s6_addr, 0, sizeof(struct in6_addr));
        // printf("add one node in list\n");
        
        for (i = 0; i < addrnum; i++) {
            conductor->addr->s6_addr[i] = in6->s6_addr[i];
        }
        conductor->length = length;
        new_pref++;
    }

    freeaddrinfo(rs);
    free(tmp);
    if (verbose) {
        inet_ntop(AF_INET6, &in6->s6_addr, buf, sizeof (buf));
        printf("[info] IPv4-only FQDN got synthesized: %s\n", buf);
        if (new_pref == 1) { 
            inet_ntop(AF_INET6, &conductor->addr->s6_addr, buf, sizeof (buf));
            printf("[info] found prefix: %s /%d\n", buf, conductor->length);
        } else {
            printf("[info] A same prefix is already in the list\n");
        }
    }

    if (m > 1) {
        fprintf(stderr, "[err] more than one prefix matched, use the longest one");
    }
    return new_pref;
}

/*
Usage:  check whether the prefix pointed by conductor is a duplicated
        one
Return: 0 -- a new prefix
        1 -- a duplicated prefix
*/
int is_duplicated_prefix(struct in6_addr *in6, int length, int addrnum)
{
    int i;
    int result = 0;
    int flag = 0;
    struct prefixs *headp;
    
    for (headp = root->next; headp != NULL; headp = headp->next) {
        if (headp->length != length)
            continue;

        for (i = 0; i < addrnum; i++) {
            if (headp->addr->s6_addr[i] != conductor->addr->s6_addr[i]) {
                flag = 1;
                break;
            }
        }

        if (flag == 0) {
            result = 1;
            break;
        }
    }

    return result;
}

/*
 * Returns n if n prefixes were found.
 */

int check_heuristic(char* ip4_fqdn, char* dnskey) {

    // struct addrinfo *ai, *res, hints;
    // struct in6_addr sa6;
    int i, prefnum;
    char buf[NI_MAXHOST];

    /*
     * We query for an AAAA record for a FQDN that we know is only 
     * provisioned with an A record.. Thus this logic fails *if*
     * the FQDN used for testing has an AAAA record. 
     */

    if ((prefnum  = dns_query(ip4_fqdn, dnskey)) == 0) {
        if (verbose) {
            printf("[info] no NAT64 detected for '%s'.\n", ip4_fqdn);
        }
    }

    return prefnum;
}
