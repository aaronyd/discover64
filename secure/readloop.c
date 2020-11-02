#include "ping.h"

void
readloop(void) {
    int size = 60 * 1024;
    int flag;
    char recvbuf[BUFSIZE];
    socklen_t len;
    ssize_t n;
    struct timeval tval;
   
    nsent = nrecv = 0;
    printf("[info] family: %d, proto: %d\n", pr->sasend->sa_family, pr->icmpproto);

    sockfd = socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);
    if (sockfd == -1) {
        err_sys("[err] initializing socket error");
    }
    
    setuid(getuid()); /* don't need special permissions any more */
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &size, sizeof (size));

    signal(SIGALRM, sig_alrm);
    alarm(2 * MAXPACKETNUM);   /* timeout value */

    while (nrecv < MAXPACKETNUM) {
        
        if (nsent < MAXPACKETNUM) {
            (*pr->fsend)();
        }

        len = sizeof (struct sockaddr_in6);
        n = recvfrom(sockfd, recvbuf, sizeof (recvbuf), 0, pr->sarecv, &len);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            } else
                err_sys("[fatal] recvfrom error");
        }

        gettimeofday(&tval, NULL);

        if (((*pr->fproc)(recvbuf, n, &tval)) == 0) {
            nrecv++;
        }
        sleep(1);
    }
    alarm(0);
}
