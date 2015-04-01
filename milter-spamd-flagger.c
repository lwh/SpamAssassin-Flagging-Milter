static const char rcsid[] = "milter-spamd-flagger 0.1 2015/04/01 12:01:45 lwh";
/*
 *
 * Copyright (c) 2004 Daniel Hartmeier
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * This is modified, differences from milter-spamd:
 *
 *		- Changed the filter to accept all mail and put the Spamassassin flag
 *			in the header as X-Spam 
 *		- Made SPAMD_RETRIES a define here, it was 6 before (6*10 seconds) 
 *		- Added a check to remove any X-Spam-Flag headers
 *		- Removed IPv6 support
 *		- Added MAX_MESSAGE_SIZE 
 */

/* Things to set */
#define USER		"_milter-spamd"
#define OCONN		"unix:/var/spool/milter-spamd/sock"
#define PIDFILE	"/var/spool/milter-spamd/pid"
/* this is x10 seconds */
#define SPAMD_RETRIES 3
#define MAX_MESSAGE_SIZE 327680
/* these are the Spamassassin defaults */
#define SPAMD_ADDR	"127.0.0.1"
#define SPAMD_PORT	783

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <pthread.h>
#include <regex.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <libmilter/mfapi.h>

static const char	*spamd_user = "";
static const char	*ignore_connect = "";
static int		 debug = 0;
static regex_t		 re_ignore_connect;
static int sf_count = 1;


struct context {
	char		 buf[2048];
	unsigned	 pos;
	char		 host[128];
	char		 addr[64];
	char		 helo[128];
	char		 env_rcpt[128];
	char		 hdr_from[128];
	char		 hdr_to[128];
	char		 hdr_subject[128];
	int		 fd;
	int		 state;
	int		 spam;
	double	 score, threshold;
	char		 symbols[128];
};

static sfsistat		 cb_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat		 cb_helo(SMFICTX *, char *);
static sfsistat		 cb_envfrom(SMFICTX *, char **);
static sfsistat		 cb_envrcpt(SMFICTX *, char **);
static sfsistat		 cb_header(SMFICTX *, char *, char *);
static sfsistat		 cb_eoh(SMFICTX *);
static sfsistat		 cb_body(SMFICTX *, u_char *, size_t);
static sfsistat		 cb_eom(SMFICTX *);
static sfsistat		 cb_abort(SMFICTX *);
static sfsistat		 cb_close(SMFICTX *);
static void		 usage(const char *);
static void		 logmsg(int, struct context *, const char *, ...);


#define	ST_MTIME st_mtimespec

static int
get_spamd_fd(struct context *context) {
	int fd;
	struct sockaddr_in sa;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		logmsg(LOG_ERR, context, "get_spamd_fd: socket: %s", strerror(errno));
		return (-1);
	}
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = inet_addr(SPAMD_ADDR);
	sa.sin_port = htons(SPAMD_PORT);
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa))) {
		logmsg(LOG_ERR, context, "get_spamd_fd: connect: %s",strerror(errno));
		close(fd);
		return (-1);
	}
	return (fd);
}

static sfsistat
cb_connect(SMFICTX *ctx, char *name, _SOCK_ADDR *sa) {
	struct context *context;
	char host[64];
	struct sockaddr_in *sin = (struct sockaddr_in *)sa;

	context = calloc(1, sizeof(*context));
	if (context == NULL) {
		/* logmsg(DEBUG, NULL, "cb_connect: calloc: %s", strerror(errno)); */
		return (SMFIS_ACCEPT);
	}
	context->fd = -1;
	if (smfi_setpriv(ctx, context) != MI_SUCCESS) {
		free(context);
		/* logmsg(LOG_DEBUG, NULL, "cb_connect: smfi_setpriv"); */
		return (SMFIS_ACCEPT);
	}

	strlcpy(host, "unknown", sizeof(host));

	if (inet_ntop(AF_INET, &sin->sin_addr.s_addr, host,
		sizeof(host)) == NULL)
		logmsg(LOG_ERR, NULL, "cb_connect: inet_ntop: %s", 
		strerror(errno)); 
	strlcpy(context->host, name, sizeof(context->host));
	strlcpy(context->addr, host, sizeof(context->addr));
	logmsg(LOG_INFO, context, "cb_connect('%s', '%s')", name, host);
	if (ignore_connect[0] && (
	    !regexec(&re_ignore_connect, name, 0, NULL, 0) ||
	    !regexec(&re_ignore_connect, host, 0, NULL, 0))) {
		/* logmsg(LOG_DEBUG, context, "cb_connect: matches host ignore RE"); */
		return (SMFIS_ACCEPT);
	}

	return (SMFIS_CONTINUE);
}

static sfsistat
cb_helo(SMFICTX *ctx, char *arg)
{
	struct context *context;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
	 	logmsg(LOG_DEBUG, NULL, "cb_helo: smfi_getpriv"); 
		return (SMFIS_ACCEPT);
	}
	strlcpy(context->helo, arg, sizeof(context->helo));
	logmsg(LOG_DEBUG, context, "cb_helo('%s')", arg);
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_envfrom(SMFICTX *ctx, char **args)
{
	struct context *context;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		logmsg(LOG_DEBUG, NULL, "cb_envfrom: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	if (*args != NULL)
		logmsg(LOG_DEBUG, context, "cb_envfrom('%s')", *args);
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_envrcpt(SMFICTX *ctx, char **args)
{
	struct context *context;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		logmsg(LOG_DEBUG, NULL, "cb_envrcpt: smfi_getpriv"); 
		return (SMFIS_ACCEPT);
	}
	if (*args != NULL) {
		strlcpy(context->env_rcpt, *args, sizeof(context->env_rcpt));
		logmsg(LOG_DEBUG, context, "cb_envrcpt('%s')", *args);
	}
	return (SMFIS_CONTINUE);
}

static void
fdprintf(int fd, const char *fmt, ...)
{
	va_list ap;
	char s[2048];

	va_start(ap, fmt);
	vsnprintf(s, sizeof(s), fmt, ap);
	va_end(ap);
	write(fd, s, strlen(s));
}

static sfsistat
cb_header(SMFICTX *ctx, char *name, char *value) {
	struct context *context;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		logmsg(LOG_DEBUG, context, "cb_header: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	logmsg(LOG_DEBUG, context, "cb_header('%s', '%s')", name, value);
	if (context->fd < 0) {
		const char *sendmail_name = smfi_getsymval(ctx, "j");
		const char *sendmail_queue = smfi_getsymval(ctx, "i");
		const char *sendmail_date = smfi_getsymval(ctx, "b");
		if ((context->fd = get_spamd_fd(context)) < 0)
			return (SMFIS_ACCEPT);
		fdprintf(context->fd, "SYMBOLS SPAMC/1.2\r\n");
		if (spamd_user[0])
			fdprintf(context->fd, "User: %s\r\n", spamd_user);
		fdprintf(context->fd, "\r\n");
		/* send fake Received: header */
		fdprintf(context->fd, "Received: from %s (%s [%s])",
			context->helo, context->host, context->addr);
		if (sendmail_name != NULL && sendmail_name[0]) {
			fdprintf(context->fd, "\r\n\tby %s (milter-spamd)",
				sendmail_name);
			if (sendmail_queue != NULL && sendmail_queue[0])
				fdprintf(context->fd, " id %s", sendmail_queue);
		}
		if (context->env_rcpt[0])
			fdprintf(context->fd, "\r\n\tfor %s", context->env_rcpt);
		if (sendmail_date != NULL && sendmail_date[0])
			fdprintf(context->fd, "; %s", sendmail_date);
		else {
			char d[128];
			time_t t = time(NULL);
			if (strftime(d, sizeof(d), "%a, %e %b %Y %H:%M:%S %z",
				localtime(&t)))
				fdprintf(context->fd, "; %s", d);
		}
		fdprintf(context->fd, "\r\n");
	}
	fdprintf(context->fd, "%s: %s\r\n", name, value);
	if (!strcasecmp(name, "From"))
		strlcpy(context->hdr_from, value, sizeof(context->hdr_from));
	else if (!strcasecmp(name, "To"))
		strlcpy(context->hdr_to, value, sizeof(context->hdr_to));
	else if (!strcasecmp(name, "Subject"))
		strlcpy(context->hdr_subject, value,
			sizeof(context->hdr_subject));
	else if (!strcasecmp(name, "X-Spam"))
		sf_count++;
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_eoh(SMFICTX *ctx)
{
	struct context *context;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		logmsg(LOG_DEBUG, NULL, "cb_eoh: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	logmsg(LOG_DEBUG, context, "cb_eoh()");
	if (context->fd >= 0)
		fdprintf(context->fd, "\r\n");
	memset(context->buf, 0, sizeof(context->buf));
	context->pos = 0;
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_body(SMFICTX *ctx, u_char *chunk, size_t size)
{
	struct context *context;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		logmsg(LOG_DEBUG, NULL, "cb_body: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	/* size check  */
	if (size >= MAX_MESSAGE_SIZE ) { 
		logmsg(LOG_DEBUG,context,"cb_connect: ignoring large message: %d",size);
		return(SMFIS_ACCEPT);
	} 
	for (; size > 0; size--, chunk++) {
		context->buf[context->pos] = *chunk;
		if (context->buf[context->pos] == '\n' ||
		    context->pos == sizeof(context->buf) - 1) {
			if (context->pos > 0 &&
			    context->buf[context->pos - 1] == '\r')
				context->buf[context->pos - 1] = 0;
			else
				context->buf[context->pos] = 0;
			context->pos = 0;
			logmsg(LOG_DEBUG, context, "cb_body('%s')", context->buf);
			if (context->fd >= 0)
				fdprintf(context->fd, "%s\r\n", context->buf);
		} else
			context->pos++;
	}
	return (SMFIS_CONTINUE);
}

static void
spamd_reply(const char *line, struct context *context, sfsistat *action)
{
	const char *p;

	switch (context->state) {
	case 0:
		if (strncmp(line, "SPAMD/", 6)) {
			logmsg(LOG_ERR, context, "spamd_reply: first reply " 
			    "not SPAMD version: %s", line);
			*action = SMFIS_ACCEPT;
			break;
		}
		p = line + 6;
		while (*p && *p != ' ')
			++p;
		while (*p == ' ')
			++p;
		if (strncmp(p, "0 EX_OK", 7)) {
			logmsg(LOG_ERR, context, "spamd_reply: first reply "
			    "not 0 EX_OK: %s", line);
			*action = SMFIS_ACCEPT;
			break;
		}
		context->state = 1;
		break;
	case 1:
		if (!strncmp(line, "Spam: ", 6)) {
			char decision[16];
			double score, threshold;

			if (sscanf(line + 6, "%15s ; %lf / %lf", decision,
			    &score, &threshold) != 3) {
				logmsg(LOG_ERR, context, "spamd_reply: malformed "
				    "decision reply: %s", line);
				*action = SMFIS_ACCEPT;
				break;
			}
			context->spam = !strcmp(decision, "True");
			context->score = score;
			context->threshold = threshold;
			context->state = 2;
		}
		break;
	case 2:
		if (!line[0])
			context->state = 3;
		break;
	case 3:
		strlcat(context->symbols, line, sizeof(context->symbols));
		break;
	default:
		/* logmsg(LOG_ERR, context, "spamd_reply: invalid context->state"); */
		*action = SMFIS_ACCEPT;
	}
}

static sfsistat
cb_eom(SMFICTX *ctx)
{
	struct context *context;
	sfsistat action = SMFIS_CONTINUE;
	char *spamflag="";
	/* char spaminfo[997]; */
	char spamscore[8];
	char buf[2048];
	int pos = 0, retry = 0;
	int sfci;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		logmsg(LOG_ERR, NULL, "cb_eom: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	logmsg(LOG_DEBUG, context, "cb_eom()");
	if (context->fd < 0)
		goto done;
	context->symbols[0] = 0;
	/* no more writing data to spamd, want to read result now */
	if (shutdown(context->fd, SHUT_WR)) {
		logmsg(LOG_ERR, context, "cb_eom: shutdown: %s", strerror(errno));
		goto done;
	}
	if (fcntl(context->fd, F_SETFL, fcntl(context->fd, F_GETFL) |
	    O_NONBLOCK)) {
		logmsg(LOG_ERR, context, "cb_eom: fcntl: %s", strerror(errno));
		goto done;
	}
	/* try at most SPAMD_RETRIES times (10 seconds timeout each) */
	while (action == SMFIS_CONTINUE && retry < SPAMD_RETRIES) {
		fd_set fds;
		struct timeval tv;
		int r, i;
		char b[8192];

		FD_ZERO(&fds);
		FD_SET(context->fd, &fds);
		tv.tv_sec = 10;
		tv.tv_usec = 0;
		r = select(context->fd + 1, &fds, NULL, NULL, &tv);
		if (r < 0) {
			if (errno != EINTR) {
				logmsg(LOG_ERR, context, "cb_eom: select: %s",
				    strerror(errno));
				break;
			}
			continue;
		} else if (r == 0 || !FD_ISSET(context->fd, &fds)) {
			retry++;
			logmsg(LOG_DEBUG, context, "cb_eom: waiting for "
			    "spamd reply (retry %d)", retry);
			continue;
		}
		r = read(context->fd, b, sizeof(b));
		if (r < 0) {
			if (errno != EINTR) {
				logmsg(LOG_ERR, context, "cb_eom: read: %s",
				    strerror(errno));
				break;
			}
			continue;
		} else if (r == 0)
			/* connection closed by spamd */
			break;
		for (i = 0; i < r; ++i)
			if (b[i] == '\n' || pos == sizeof(buf) - 1) {
				if (pos > 0 && buf[pos - 1] == '\r')
					buf[pos - 1] = 0;
				else
					buf[pos] = 0;
				/* sets action when done */
				spamd_reply(buf, context, &action);
				pos = 0;
			} else
				buf[pos++] = b[i];
	}
	if (retry == SPAMD_RETRIES)
		logmsg(LOG_ERR, context, "cb_eom: spamd connection timed out");
	done:
	if (context->fd >= 0) {
		close(context->fd);
		context->fd = -1;
	}
	/* either way, we don't want to continue */
	if (action == SMFIS_CONTINUE)
	action = SMFIS_ACCEPT;
	logmsg(LOG_INFO, context,
	    "(Flag:%s , %.1f/%.1f %s), From: %s, To: %s, Subject: %s",
	    (context->spam ? "Yes" : "No"), context->score, context->threshold,
	    context->symbols, context->hdr_from,
		 context->hdr_to, context->hdr_subject);
	for (sfci=1;sfci<sf_count;sfci++) {
		if(smfi_chgheader(ctx, "X-Spam", sfci ,NULL) != MI_SUCCESS) { 
			logmsg(LOG_DEBUG, context, "Failed to erase X-Spam header");
		}
		else {
			logmsg(LOG_DEBUG,context,"Erased X-Spam %d",sfci);
		}
	}
	if (context->spam) { spamflag="Yes"; } else { spamflag="No"; }
	if(smfi_addheader(ctx, "X-Spam", spamflag) != MI_SUCCESS) {
		logmsg(LOG_DEBUG, context, "Failed to add X-Spam header");
	}
	sprintf(spamscore,"%.1f",context->score);
	if(smfi_addheader(ctx, "X-SA-score", spamscore ) != MI_SUCCESS) {
		logmsg(LOG_DEBUG, context, "Failed to add Spam-Score header");
	}

	context->pos = context->hdr_from[0] = context->hdr_to[0] =
	    context->hdr_subject[0] = context->state = context->spam =
	    context->symbols[0] = 0;
	context->score = context->threshold = 0.0;
	return (action);
}

static sfsistat
cb_abort(SMFICTX *ctx)
{
	struct context *context;

	if ((context = (struct context *)smfi_getpriv(ctx)) == NULL) {
		logmsg(LOG_ERR, NULL, "cb_abort: smfi_getpriv");
		return (SMFIS_ACCEPT);
	}
	logmsg(LOG_DEBUG, context, "cb_abort()");
	if (context->fd >= 0) {
		close(context->fd);
		context->fd = -1;
	}
	context->pos = context->hdr_from[0] = context->hdr_to[0] =
	    context->hdr_subject[0] = context->state = context->spam =
	    context->symbols[0] = 0;
	context->score = context->threshold = 0.0;
	return (SMFIS_CONTINUE);
}

static sfsistat
cb_close(SMFICTX *ctx)
{
	struct context *context;

	context = (struct context *)smfi_getpriv(ctx);
	logmsg(LOG_DEBUG, context, "cb_close()");
	if (context != NULL) {
		smfi_setpriv(ctx, NULL);
		if (context->fd >= 0) {
			close(context->fd);
			context->fd = -1;
		}
		free(context);
	}
	return (SMFIS_CONTINUE);
}

struct smfiDesc smfilter = {
	"milter-spamd-flagger",	/* filter name */
	SMFI_VERSION,	/* version code -- do not change */
	SMFIF_ADDHDRS|SMFIF_CHGHDRS,		/* flags */
	cb_connect,	/* connection info filter */
	cb_helo,	/* SMTP HELO command filter */
	cb_envfrom,	/* envelope sender filter */
	cb_envrcpt,	/* envelope recipient filter */
	cb_header,	/* header filter */
	cb_eoh,		/* end of header */
	cb_body,	/* body block */
	cb_eom,		/* end of message */
	cb_abort,	/* message aborted */
	cb_close,	/* connection cleanup */
};

static void
usage(const char *argv0) {
	fprintf(stderr, "usage: %s [-d] [-i Regex] [-u user] [-U spamd user] "
		"[-p pipe]\n", argv0);
	exit(1);
}

int
main(int argc, char **argv) {
	int ch;
	FILE *fp;
	const char *oconn = OCONN;
	const char *user = USER;
	sfsistat r = MI_FAILURE;
	const char *ofile = NULL;
	unsigned int mypid=0;

	tzset();
	openlog("milter-s-f", LOG_PID | LOG_NDELAY, LOG_MAIL);
	fp=fopen(PIDFILE,"w");
	if (fp != NULL) {
		fprintf(fp,"%d\n",mypid);
		(void)fclose(fp);
	}

while ((ch = getopt(argc, argv, "di:p:u:U:")) != -1) {
				  switch (ch) {
				  case 'd':
					  debug = 1;
					  break;
				  case 'i':  {
					  int r;

					  ignore_connect = optarg;
					  r = regcomp(&re_ignore_connect, ignore_connect,
							REG_EXTENDED | REG_ICASE);
					  if (r) {
						  char e[8192];

						  regerror(r, &re_ignore_connect, e, sizeof(e));
						  fprintf(stderr, "regcomp: %s: %s\n",
								ignore_connect, e);
						  usage(argv[0]);
					  }
					  break;
				  }
				  case 'p':
					  oconn = optarg;
					  break;
				  case 'u':
					  user = optarg;
					  break;
				  case 'U':
					  spamd_user = optarg;
					  break;
				  default:
					  usage(argv[0]);
				  }
			  }
			  if (argc != optind) {
				  fprintf(stderr, "unknown command line argument: %s ...",
						argv[optind]);
				  usage(argv[0]);
			  }

			  if (!strncmp(oconn, "unix:", 5))
				  ofile = oconn + 5;
			  else if (!strncmp(oconn, "local:", 6))
				  ofile = oconn + 6;
			  if (ofile != NULL)
				  unlink(ofile);

			  /* drop privileges */
			  if (!getuid()) {
				  struct passwd *pw;

				  if ((pw = getpwnam(user)) == NULL) {
					  fprintf(stderr, "getpwnam: %s: %s\n", user,
							strerror(errno));
					  return (1);
				  }
				  setgroups(1, &pw->pw_gid);
				  if (setegid(pw->pw_gid) || setgid(pw->pw_gid)) {
					  fprintf(stderr, "setgid: %s\n", strerror(errno));
					  return (1);
				  }
				  if (
						seteuid(pw->pw_uid) ||
						setuid(pw->pw_uid)) {
					  fprintf(stderr, "setuid: %s\n", strerror(errno));
					  return (1);
				  }
			  }

			  if (smfi_setconn((char *)oconn) != MI_SUCCESS) {
				  fprintf(stderr, "smfi_setconn: %s: failed\n", oconn);
				  goto done;
			  }

			  if (smfi_register(smfilter) != MI_SUCCESS) {
				  fprintf(stderr, "smfi_register: failed\n");
				  goto done;
			  }

			  /* daemonize (detach from controlling terminal) */
			  if (!debug && daemon(0, 0)) {
				  fprintf(stderr, "daemon: %s\n", strerror(errno));
				  goto done;
			  }
			  umask(0177);
			  signal(SIGPIPE, SIG_IGN);

	logmsg(LOG_INFO, NULL, "started: %s", rcsid); 
	r = smfi_main();
	if (r != MI_SUCCESS)
	logmsg(LOG_ERR, NULL, "smfi_main: terminating due to error:\n%s (%d)",strerror(errno),errno);
	else
	logmsg(LOG_DEBUG, NULL, "smfi_main: terminating without error");

done:
	return (r);
}

static void
logmsg(int priority, struct context *context, const char *fmt, ...)
{
	va_list ap;
	char msg[8192];

	va_start(ap, fmt);
	if (context != NULL)
		snprintf(msg, sizeof(msg), "%s: ", context->addr);
	else
		msg[0] = 0;
	vsnprintf(msg + strlen(msg), sizeof(msg) - strlen(msg), fmt, ap);
	if (debug) {
		printf("syslog: %s\n", msg);
		syslog(priority, "%s", msg);
	}
	else {
		if (priority != LOG_DEBUG)
			syslog(priority, "%s", msg);
	}
	va_end(ap);
}

