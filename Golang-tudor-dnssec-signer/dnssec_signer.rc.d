#!/bin/sh

# PROVIDE: dnssec_signer
# REQUIRE: LOGIN
# BEFORE: nsd
# KEYWORD: shutdown

# Add the following lines to /etc/rc.conf to enable dnssec_signer:
#
# dnssec_signer_enable="YES"
# dnssec_signer_config="/usr/local/etc/tudordns/dnssec-signer.toml"
# dnssec_signer_web="127.0.0.1:8053"  # Optional: enable web UI (loopback only;
#                                     # a non-loopback address needs web.allow_remote=true)
#
# Create the service user and group before starting:
#   pw groupadd -n dnssec
#   pw useradd -n dnssec -g dnssec -d /nonexistent -s /usr/sbin/nologin -c "DNSSEC Signer"
#   mkdir -p /usr/local/etc/tudordns /var/db/dnssec-tudor
#   chown dnssec:dnssec /var/db/dnssec-tudor

. /etc/rc.subr

name="dnssec_signer"
rcvar="${name}_enable"

load_rc_config $name

: ${dnssec_signer_enable:="NO"}
: ${dnssec_signer_user:="dnssec"}
: ${dnssec_signer_group:="dnssec"}
: ${dnssec_signer_config:="/usr/local/etc/tudordns/dnssec-signer.toml"}
: ${dnssec_signer_pidfile:="/var/run/${name}.pid"}
: ${dnssec_signer_logfile:="/var/log/${name}.log"}
: ${dnssec_signer_web:=""}

pidfile="${dnssec_signer_pidfile}"
command="/usr/local/bin/dnssec-tudor"

start_cmd="${name}_start"
stop_cmd="${name}_stop"
status_cmd="${name}_status"
restart_cmd="${name}_restart"
reload_cmd="${name}_reload"
extra_commands="reload"

dnssec_signer_start()
{
    echo "Starting ${name}."
    if [ -f "${pidfile}" ] && kill -0 $(cat ${pidfile}) 2>/dev/null; then
        echo "${name} is already running as pid $(cat ${pidfile})"
        return 1
    fi

    # Build command args
    _args="serve --config ${dnssec_signer_config}"
    if [ -n "${dnssec_signer_web}" ]; then
        _args="${_args} --web ${dnssec_signer_web}"
    fi

    /usr/sbin/daemon -c -p ${pidfile} -u ${dnssec_signer_user} \
        -o ${dnssec_signer_logfile} \
        ${command} ${_args}
}

dnssec_signer_stop()
{
    if [ -f "${pidfile}" ]; then
        echo "Stopping ${name}."
        kill -TERM $(cat ${pidfile}) 2>/dev/null
        wait_for_pids $(cat ${pidfile})
        rm -f ${pidfile}
    else
        echo "${name} is not running."
    fi
}

dnssec_signer_status()
{
    if [ -f "${pidfile}" ] && kill -0 $(cat ${pidfile}) 2>/dev/null; then
        echo "${name} is running as pid $(cat ${pidfile})"
    else
        echo "${name} is not running"
        return 1
    fi
}

dnssec_signer_restart()
{
    dnssec_signer_stop
    sleep 1
    dnssec_signer_start
}

dnssec_signer_reload()
{
    if [ -f "${pidfile}" ]; then
        echo "Reloading ${name} configuration."
        kill -HUP $(cat ${pidfile})
    else
        echo "${name} is not running."
        return 1
    fi
}

run_rc_command "$1"
