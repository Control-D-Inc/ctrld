#!/bin/sh
set -eu

iface=$(/sbin/route -n get default 2>/dev/null | /usr/bin/awk '/interface:/{print $2; exit}')

printf 'default_interface=%s\n' "$iface"

printf 'ipv4_address='
/usr/sbin/ipconfig getifaddr "$iface" 2>/dev/null || printf '<none>\n'

printf 'dhcp_ipv4_dns='
/usr/sbin/ipconfig getoption "$iface" domain_name_server 2>/dev/null |
    /usr/bin/awk '
        {
            for (i = 1; i <= NF; i++) {
                value = $i
                gsub(/[{},;]/, "", value)
                if (value ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ && !seen[value]++) {
                    if (found) {
                        printf ","
                    }
                    printf "%s", value
                    found = 1
                }
            }
        }
        END {
            if (!found) {
                printf "<none>"
            }
            printf "\n"
        }
    '

printf 'effective_ipv4_dns='
/usr/sbin/scutil --dns |
    /usr/bin/awk '
        /nameserver\[[0-9]+\] : [0-9]+\./ {
            if (!seen[$3]++) {
                if (found) {
                    printf ","
                }
                printf "%s", $3
                found = 1
            }
        }
        END {
            if (!found) {
                printf "<none>"
            }
            printf "\n"
        }
    '
