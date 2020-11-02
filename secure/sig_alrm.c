#include "ping.h"

void
sig_alrm(int signo) {
    nrecv = MAXPACKETNUM + 1;
    return; /* probably interrupts recvfrom() */
}
