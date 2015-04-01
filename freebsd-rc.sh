#!/bin/sh
#
# PROVIDE: miltersf
# REQUIRE: LOGIN
# BEFORE: mail
# KEYWORD: FreeBSD shutdown
#
# use milter-spamd-flagger_enable="YES" and
# place this in /usr/local/etc/rc.d/ or your own local startup
# directories.
# required_dirs may change if you change it in the source
# as well as the socket file in stop_postcmd
. /etc/rc.subr

name=miltersf
rcvar=`set_rcvar`

command=/usr/local/sbin/milter-spamd-flagger
required_dirs=/var/spool/milter-spamd

stop_postcmd=stop_postcmd

stop_postcmd()
{
  rm -f $pidfile
  rm -f /var/spool/milter-spamd/sock
}

# set defaults

miltersf_enable=${miltersf_enable:-"NO"}
miltersf_pidfile=${miltersf_pidfile:-"/var/spool/milter-spamd/pid"}
miltersf_flags=${miltersf_flags:-""}

load_rc_config $name
run_rc_command "$1"
