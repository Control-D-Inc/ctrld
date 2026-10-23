package ctrld

import (
	"net"
	"strings"
	"unicode"
)

func parseDHCPOptionNameservers(output []byte) []string {
	return parseIPv4Nameservers(string(output))
}

func parseDHCPPacketNameservers(output []byte) []string {
	for _, line := range strings.Split(string(output), "\n") {
		field := strings.TrimSpace(line)
		if strings.HasPrefix(field, "domain_name_server ") ||
			strings.HasPrefix(field, "domain_name_server:") ||
			strings.HasPrefix(field, "domain_name_servers ") ||
			strings.HasPrefix(field, "domain_name_servers:") {
			return parseIPv4Nameservers(field)
		}
	}
	return nil
}

func parseIPv4Nameservers(value string) []string {
	seen := make(map[string]struct{})
	var nameservers []string
	for _, token := range strings.FieldsFunc(value, func(r rune) bool {
		return r != '.' && !unicode.IsDigit(r)
	}) {
		ip := net.ParseIP(token)
		if ip == nil || ip.To4() == nil {
			continue
		}
		ns := ip.String()
		if _, ok := seen[ns]; ok {
			continue
		}
		seen[ns] = struct{}{}
		nameservers = append(nameservers, ns)
	}
	return nameservers
}
