# $Id: Makefile,v 1.1.1.1 2004/04/03 20:27:00 dhartmei Exp $

PROG=	milter-spamd-flagger
SRCS=	milter-spamd-flagger.c
MAN=	milter-spamd-flagger.8
BINDIR=/usr/local/sbin
MANDIR=/usr/share/man/man
CFLAGS+=	-O -pipe
CFLAGS+=	-I/usr/src/gnu/usr.sbin/sendmail/include
LDADD+=		-lmilter -pthread

.include <bsd.prog.mk>

