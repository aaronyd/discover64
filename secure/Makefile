OBJS = main.o proc_v4.o proc_v6.o readloop.o \
		send_v4.o send_v6.o sig_alrm.o tv_sub.o in_cksum.o \
		heuristics.o error.o 
PROGS =	ping64
CFLAGS += -D HAVE_GETADDRINFO_PROTO -D USING_OSX
LIBS += -lresolv -lunbound

all:	${PROGS}

ping64:	${OBJS}
		${CC} ${CFLAGS} -o $@ ${OBJS} ${LIBS} -Wall -g 

clean:
		rm -f ${OBJS} ${PROGS} ${CLEANFILES}
