package cli

import "golang.org/x/sys/windows"

func hasElevatedPrivilege() (bool, error) {
	var sid *windows.SID
	if err := windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0,
		0,
		0,
		0,
		0,
		0,
		&sid,
	); err != nil {
		return false, err
	}
	token := windows.Token(0)
	return token.IsMember(sid)
}
