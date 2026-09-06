#!/bin/sh

# PROVIDE: sigillum_signer
# REQUIRE: LOGIN
# BEFORE: nsd
# KEYWORD: shutdown

# Add the following lines to /etc/rc.conf to enable sigillum_signer:
#
# sigillum_signer_enable="YES"
# sigillum_signer_config="/usr/local/etc/sigillum-signer/config.toml"
# sigillum_signer_web="127.0.0.1:8053"  # Optional: enable web UI (loopback only;
#                                     # a non-loopback address needs web.allow_remote=true)
#
# Create the service user and group before starting:
#   pw groupadd -n sigillum-signer
#   pw useradd -n sigillum-signer -g sigillum-signer -d /nonexistent -s /usr/sbin/nologin -c "DNSSEC Signer"
#   mkdir -p /usr/local/etc/sigillum-signer /var/db/sigillum-signer
#   chown sigillum-signer:sigillum-signer /var/db/sigillum-signer

. /etc/rc.subr

name="sigillum_signer"
rcvar="${name}_enable"

load_rc_config $name

: ${sigillum_signer_enable:="NO"}
: ${sigillum_signer_svcuser:="sigillum-signer"}
: ${sigillum_signer_config:="/usr/local/etc/sigillum-signer/config.toml"}
: ${sigillum_signer_pidfile:="/var/run/sigillum-signer.pid"}
: ${sigillum_signer_logfile:="/var/log/sigillum-signer.log"}
: ${sigillum_signer_web:=""}

pidfile="${sigillum_signer_pidfile}"
command="/usr/local/bin/sigillum-signer"

# daemon(8) drops privileges; avoid rc.subr’s special ${name}_user wrapper.
start_cmd="${name}_start"
stop_cmd="${name}_stop"
status_cmd="${name}_status"
restart_cmd="${name}_restart"
reload_cmd="${name}_reload"
extra_commands="reload"

sigillum_signer_start()
{
    echo "Starting ${name}."
    if [ -f "${pidfile}" ] && kill -0 $(cat ${pidfile}) 2>/dev/null; then
        echo "${name} is already running as pid $(cat ${pidfile})"
        return 1
    fi

    # Build command args
    _args="serve --config ${sigillum_signer_config}"
    if [ -n "${sigillum_signer_web}" ]; then
        _args="${_args} --web ${sigillum_signer_web}"
    fi

    # -f detaches daemon(8)'s own inherited stdio. Without it `service sigillum-signer start`
    # over ssh never returns — the supervisor holds the pipe until the process exits.
    # It does not replace -o/-S below: those route the child's output, -f the parent's.
    /usr/sbin/daemon -f -c -p ${pidfile} -u ${sigillum_signer_svcuser} \
        -o ${sigillum_signer_logfile} \
        ${command} ${_args}
}

sigillum_signer_stop()
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

sigillum_signer_status()
{
    if [ -f "${pidfile}" ] && kill -0 $(cat ${pidfile}) 2>/dev/null; then
        echo "${name} is running as pid $(cat ${pidfile})"
    else
        echo "${name} is not running"
        return 1
    fi
}

sigillum_signer_restart()
{
    sigillum_signer_stop
    sleep 1
    sigillum_signer_start
}

sigillum_signer_reload()
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
