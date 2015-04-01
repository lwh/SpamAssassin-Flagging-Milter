# This will only build on BSD

PROG=	milter-spamd-flagger
SRCS=	milter-spamd-flagger.c
MAN=	milter-spamd-flagger.8
BINDIR=/usr/local/sbin
MANDIR=/usr/share/man/man
CFLAGS+=	-O -pipe
CFLAGS+=	-I/usr/src/gnu/usr.sbin/sendmail/include
LDADD+=		-lmilter -pthread

.include <bsd.prog.mk>

