#include "ping.h"

#include <getopt.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

struct proto proto_v4 = {proc_v4, send_v4, NULL, NULL, 0, IPPROTO_ICMP};
struct proto proto_v6 = {proc_v6, send_v6, NULL, NULL, 0, IPPROTO_ICMPV6};

static int force6 = 0;
static int avoid64 = 0;

/*
 * Synthesize function implements current RFC6052 address synthesis. Suffix
 * bits are all zeroed. u and g bits are zeroes (the 'u' part of the synthesized
 * address.
 *
 * Parameters:
 *   pref64    [in] the known pref64 (whether WKP and NSP)
 *   ipv4      [in] the IPv4 address used for synthesis
 *   pref64len [in] the length of the pref64 (32,40,48,56,64 or 96)
 *   synth6    [out] the synthesized IPv6 address
 * Return:
 *   0 if OK, -1 if error (e.g. the pref64len is unknown)
 *
 */

static int synthesize(const struct sockaddr_in6* pref64, /* pref64 */
        const struct sockaddr_in* ipv4, /* IPv4 address */
        int pref64len, /* pref64 length */
        struct sockaddr_in6* synth6) /* synthesized IPv6 address */ {
    int n, m;
    uint8_t* ipv4ptr = (uint8_t*) & ipv4->sin_addr.s_addr;

    memset(synth6, 0, sizeof (struct sockaddr_in6));
    synth6->sin6_family = AF_INET6;

    n = pref64len >> 3;

    for (m = 0; m < n; m++) {
        synth6->sin6_addr.s6_addr[m] = pref64->sin6_addr.s6_addr[m];
    }

    switch (pref64len) {
        case 32:
            for (n = 0; n < 4; n++) {
                synth6->sin6_addr.s6_addr[n + 4] = ipv4ptr[n];
            }
            return 0;

        case 40:
            for (n = 0; n < 3; n++) {
                synth6->sin6_addr.s6_addr[n + 5] = ipv4ptr[n];
            }
            synth6->sin6_addr.s6_addr[9] = ipv4ptr[3];
            return 0;

        case 48:
            for (n = 0; n < 2; n++) {
                synth6->sin6_addr.s6_addr[n + 6] = ipv4ptr[n];
                synth6->sin6_addr.s6_addr[n + 9] = ipv4ptr[n + 2];
            }
            return 0;

        case 56:
            synth6->sin6_addr.s6_addr[7] = ipv4ptr[0];

            for (n = 0; n < 3; n++) {
                synth6->sin6_addr.s6_addr[n + 9] = ipv4ptr[n + 1];
            }
            return 0;

        case 64:
            for (n = 0; n < 4; n++) {
                synth6->sin6_addr.s6_addr[n + 9] = ipv4ptr[n];
            }
            return 0;

        case 96:
            for (n = 0; n < 4; n++) {
                synth6->sin6_addr.s6_addr[n + 12] = ipv4ptr[n];
            }
            return 0;

        default:
            break;
    }

    return -1;
}

/*
 * Main program
 */

int datalen = 56;

int main(int argc, char **argv) {
    char* fqdn = NULL;
    char* keys = NULL;
    int i, j, c, ai_flags, init_flag;
    struct addrinfo *res, hints;
    struct sockaddr_in6 pref64;
    struct sockaddr_in6 *addr, synth6;
    struct stat sb;
    int addrlen;
    int pref64len;
    int pref64num;  /* number of pref64 stored in the linked list */
    int err;
    char buf[256];
    char *str;

    opterr = 0; /* Don't want getopt() writing to stderr. */
    while ((c = getopt(argc, argv, "sa6vu:k:")) != -1) {
        switch (c) {
            case 's':
                security = 1; /* security exchange */
                break;
            case 'k': /* DNSSEC public keys (or DS) */
                keys = optarg;
                break;
            case 'v':
                verbose++;
                break;
            case 'u': /* JiK (IPv4 only host name) */
                fqdn = optarg;
                break;
            case '6':
                force6 = 1;
                break;
            case 'a':
                avoid64 = 1;
                break;
            case '?':
                err_quit("unrecognized option: %c", c);
        }
    }

    if (optind != argc - 1 || (security == 1 && keys == NULL))
        err_quit("usage: ping [ -6 -v -u <v4fqdn> -s -k <key>] <hostname>");
    
    if (keys) { /* check the keys file */
        if (stat(keys, &sb) == -1) {
            err_sys("[err] %s -- stat error", keys);
        }

        if (!S_ISREG(sb.st_mode)) {
            err_quit("[err] invalid keys file");
        }
    }

    host = argv[optind];

    pid = getpid();
    signal(SIGALRM, sig_alrm);

    memset(&synth6, 0, sizeof (synth6));
    addrlen = 0;

    memset(&pref64, 0, sizeof (pref64));
    pref64.sin6_family = AF_INET6;

    if (fqdn == NULL) {
        fqdn = getenv("IPV4ONLYFQDN");
    }

    /*
     *  Check heuristics..
     */

    if (fqdn) {
        if (verbose) {
            printf("[info] IPv4-only FQDN for heuristics: %s\n", fqdn);
        }

        // create the linked list
        if ((root = malloc (sizeof(struct prefixs))) == NULL) {
            err_sys("[fatal] malloc -- out of memory");
        }
        
        root->next = NULL;
        conductor = root;

        pref64num = check_heuristic(fqdn, keys); /* func in heruistics.c */
    } else {
        /* We have no synthesis information -> pref64len = 0 */
        pref64num = 0;
        pref64len = 0;
    }

    /*
     * Check if we got an IPv4 or IPv6 FQDN.. or an IP address.
     */

    ai_flags = 0;
    if (inet_pton(AF_INET, host, buf) > 0) {
        ai_flags |= AI_NUMERICHOST; /* IPv4 address */
    } else if (inet_pton(AF_INET6, host, buf) > 0) {
        ai_flags |= AI_NUMERICHOST; /* IPv6 address */
    } else { /* FQDN */
        // force6 = 0;
    }

    // printf("sleep start\n");
    // sleep(60);

    /* 
     * In a greedy manner pick up the destination that the
     * system thinks is the best suited for us.
     */

    memset(&hints, 0, sizeof (hints));
    hints.ai_flags = AI_CANONNAME | ai_flags;
    hints.ai_family = AF_INET6;
    err = -1;

    if (!(err = getaddrinfo(host, NULL, &hints, &res))) { 
        /* get IPv6 address */
        if (avoid64 == 1) { 
            /* avoid to use the ipv6 address provided 
            by NAT64 middlebox */        
            init_flag = 0;
            for(i = 0; i < pref64num; i++) {
                if (init_flag == 0) {
                    conductor = root->next;
                    init_flag = 1;
                } else {
                    conductor = conductor->next;
                }
                
                pref64len = conductor->length;
                for (j = 0; j < 12; j++) {
                    pref64.sin6_addr.s6_addr[j] 
                        = conductor->addr->s6_addr[j];
                }
                
                if (pref64len > 0 
                        && equal_prefix((struct sin6_addr*) &(((struct sockaddr_in6*) (res->ai_addr))->sin6_addr),
                        &pref64.sin6_addr, pref64len)) {
                    err = -1;
                    break;
                }
            }
        }
        
        if (avoid64 != 1 || err != -1) {
            str = inet_ntop(AF_INET6,
                    (struct sin6_addr*) &(((struct sockaddr_in6*) (res->ai_addr))->sin6_addr),
                    buf, sizeof (buf));
            /* v6 found.. don't force synthesis.. */
            force6 = 0;
        }
    }

    if (err) { /* try to get an ipv4 address */
        memset(&hints, 0, sizeof (hints));
        hints.ai_flags = AI_CANONNAME | ai_flags;
        hints.ai_family = AF_INET;

        if (!(err = getaddrinfo(host, NULL, &hints, &res))) {
            str = inet_ntop(AF_INET,
                    (struct sin_addr*) &(((struct sockaddr_in*) (res->ai_addr))->sin_addr),
                    buf, sizeof (buf));
        }
    }
    if (err || str == NULL) {
        err_quit("[err] %s\n", gai_strerror(err));
    }

    addr = (struct sockaddr_in6 *)res->ai_addr;
    addr->sin6_family = res->ai_family;

    // synthesis and ping loop with different prefixs in the linked list
    init_flag = 0; /* first time to use the linked list */
    do { 
        if (pref64num > 0) {
            if (init_flag == 0) {
                conductor = root->next;
                init_flag = 1;
            } else {
                conductor = conductor->next;
            }
            
            pref64len = conductor->length;
            for (j = 0; j < 12; j++) {
                pref64.sin6_addr.s6_addr[j] 
                    = conductor->addr->s6_addr[j];
            }
            pref64num--;

            if (force6 && pref64len > 0) {
                if (verbose) {
                    printf("[info] IPv4 dest, trying to force synthesis\n");
                }

                addr = &synth6;
                addr->sin6_family = AF_INET6;

                inet_ntop(AF_INET6, &pref64.sin6_addr, buf, sizeof (buf));

                if (verbose) {
                    printf("[info] pref64 known:  %s/%d\n", buf, pref64len);
                }

                synthesize(&pref64,
                        (struct sockaddr_in*) (res->ai_addr),
                        pref64len,
                        addr);

                inet_ntop(AF_INET6, &addr->sin6_addr, buf, sizeof (buf));

                if (verbose) {
                    printf("[info] synthesized: %s/%d\n", buf, pref64len);
                }
            } else {
                /* We are not interested in synthesized addresses. */
                pref64len = 0;
            }
        }

        // start to ping
        printf("[info] PING %s (%s): %d data bytes\n", host, buf, datalen);

        /* 4initialize according to protocol */
        if (addr->sin6_family == AF_INET) {
            pr = &proto_v4;
        } else if (addr->sin6_family == AF_INET6) {
            pr = &proto_v6;
            if (IN6_IS_ADDR_V4MAPPED(&addr->sin6_addr))
                err_quit("[err] cannot ping IPv4-mapped IPv6 address");
        } else {
            err_quit("[err] unknown address family %d", addr->sin6_family);
        }
           
        pr->sasend = (struct sockaddr *) addr;
        pr->sarecv = malloc(sizeof (struct sockaddr_in6));
        pr->salen = (sizeof (struct sockaddr_in6));
        readloop();
        printf("[info] PING %s (%s) finished\n", host, buf);
    } while (pref64num > 0); /* try to use every prefix */

    free(pr->sarecv);
    freeaddrinfo(res);

    if (fqdn) { /* free the linked list */
        struct prefixs *tmp;
        conductor = root->next;
        while (conductor != NULL) {
            tmp = conductor;
            conductor = conductor->next;
            free(tmp);
        }
        free(root);
    }

    exit(0);
}
