package dnsrcode

import "strings"

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
var dnsRcode = map[string]int{
	"NOERROR":   0,  // NoError   - No Error
	"FORMERR":   1,  // FormErr   - Format Error
	"SERVFAIL":  2,  // ServFail  - Server Failure
	"NXDOMAIN":  3,  // NXDomain  - Non-Existent Domain
	"NOTIMP":    4,  // NotImp    - Not Implemented
	"REFUSED":   5,  // Refused   - Query Refused
	"YXDOMAIN":  6,  // YXDomain  - Name Exists when it should not
	"YXRRSET":   7,  // YXRRSet   - RR Set Exists when it should not
	"NXRRSET":   8,  // NXRRSet   - RR Set that should exist does not
	"NOTAUTH":   9,  // NotAuth   - Server Not Authoritative for zone
	"NOTZONE":   10, // NotZone   - Name not contained in zone
	"BADSIG":    16, // BADSIG    - TSIG Signature Failure
	"BADVERS":   16, // BADVERS   - Bad OPT Version
	"BADKEY":    17, // BADKEY    - Key not recognized
	"BADTIME":   18, // BADTIME   - Signature out of time window
	"BADMODE":   19, // BADMODE   - Bad TKEY Mode
	"BADNAME":   20, // BADNAME   - Duplicate key name
	"BADALG":    21, // BADALG    - Algorithm not supported
	"BADTRUNC":  22, // BADTRUNC  - Bad Truncation
	"BADCOOKIE": 23, // BADCOOKIE - Bad/missing Server Cookie
}

// FromString returns the DNS Rcode number from given DNS Rcode string.
// The string value is treated as case-insensitive. If the input string
// is an invalid DNS Rcode, -1 is returned.
func FromString(rcode string) int {
	rcode = strings.ToUpper(rcode)
	val, ok := dnsRcode[rcode]
	if !ok {
		return -1
	}
	return val
}
