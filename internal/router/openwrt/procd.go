package openwrt

const openWrtScript = `#!/bin/sh /etc/rc.common
USE_PROCD=1
# After network starts
START=21
# Before network stops
STOP=89
cmd="{{.Path}}{{range .Arguments}} {{.|cmd}}{{end}}"
name="{{.Name}}"
pid_file="/var/run/${name}.pid"

start_service() {
    echo "Starting ${name}"
    procd_open_instance
    procd_set_param command ${cmd}
    procd_set_param respawn             # respawn automatically if something died
    procd_set_param stdout 1            # forward stdout of the command to logd
    procd_set_param stderr 1            # same for stderr
    procd_set_param pidfile ${pid_file} # write a pid file on instance start and remove it on stop
    procd_close_instance
    echo "${name} has been started"
}
`
