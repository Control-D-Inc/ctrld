package netgear

const openWrtScript = `#!/bin/sh /etc/rc.common
USE_PROCD=1
# After dnsmasq starts
START=61
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
    procd_set_param pidfile ${pid_file} # write a pid file on instance start and remove it on stop
    procd_close_instance
    echo "${name} has been started"
}
`
