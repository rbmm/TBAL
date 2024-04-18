#include "stdafx.h"
#include "log.h"
#include "common.h"

PCSTR GetLogonTypeName(ULONG LogonType, PSTR buf, ULONG cch)
{
#define CASE_LT(x) case x: return #x;

	switch(LogonType)
	{
		CASE_LT(UndefinedLogonType);
		CASE_LT(Interactive);
		CASE_LT(Network);
		CASE_LT(Batch);
		CASE_LT(Service);
		CASE_LT(Proxy);
		CASE_LT(Unlock);
		CASE_LT(NetworkCleartext);
		CASE_LT(NewCredentials);
		CASE_LT(RemoteInteractive);
		CASE_LT(CachedInteractive);
		CASE_LT(CachedRemoteInteractive);
		CASE_LT(CachedUnlock);
	}

	sprintf_s(buf, cch, "[%x]", LogonType);
	return buf;
}

PSTR FormatUserFlags(LONG UserFlags, PSTR loc_buf, ULONG loc_cch)
{
	static const PCSTR _S_szFlags[32] = {
		"GUEST",
		"NOENCRYPTION",
		"CACHED_ACCOUNT",
		"USED_LM_PASSWORD",
		0,
		"EXTRA_SIDS",
		"SUBAUTH_SESSION_KEY",
		"SERVER_TRUST_ACCOUNT",
		"NTLMV2_ENABLED",
		"RESOURCE_GROUPS",
		"PROFILE_PATH_RETURNED",
		"NT_V2",
		"LM_V2",
		"NTLM_V2",
		"OPTIMIZED",
		"WINLOGON",
		"PKINIT",
		"NO_OPTIMIZED",
		"NO_ELEVATION",
		"MANAGED_SERVICE",
	};

	SIZE_T cch = 0;
	PCSTR pcsz;
	int i = 32;
	do 
	{
		if (_bittest(&UserFlags, --i) && (pcsz = _S_szFlags[i]))
		{
			// \t\t%s\r\n
			cch += strlen(pcsz) + 4;
		}
	} while (i);

	if (!cch)
	{
		*loc_buf = 0;
		return loc_buf;
	}

	if (PSTR buf = ++cch > loc_cch ? new CHAR[cch] : loc_buf)
	{
		PSTR psz = buf;
		i = 32;
		do 
		{
			if (_bittestandreset(&UserFlags, --i) && (pcsz = _S_szFlags[i]))
			{
				int len = sprintf_s(psz, cch, "\t\t%s\r\n", pcsz);
				if (0 >= len)
				{
					delete [] buf;
					return 0;
				}
				psz += len, cch -= len;
			}
		} while (UserFlags);

		return buf;
	}

	return 0;
}

void Dump(PSECURITY_LOGON_SESSION_DATA LogonSessionData)
{
	CHAR szLogonType[16], buf[0x80];
	UNICODE_STRING SidString {};
	RtlConvertSidToUnicodeString(&SidString, LogonSessionData->Sid, TRUE);
	TIME_FIELDS tf;
	RtlTimeToTimeFields(&LogonSessionData->LogonTime, &tf);

	PSTR pszFlags = FormatUserFlags(LogonSessionData->UserFlags, buf, _countof(buf));

	DbgPrint("========SECURITY_LOGON_SESSION_DATA: {%08X-%08X} %s [%u] %08X\r\n"
		"%s"
		"LogonTime     : %u-%02u-%02u %02u:%02u:%02u\r\n"
		"Sid           : %wZ\r\n"
		"UserName      : %wZ\r\n"
		"LogonDomain   : %wZ\r\n"
		"DnsDomainName : %wZ\r\n"
		"Upn           : %wZ\r\n"
		"LogonServer   : %wZ\r\n"
		"AuthPackage   : %wZ\r\n"
		"\r\n", 
		LogonSessionData->LogonId.HighPart, LogonSessionData->LogonId.LowPart,
		GetLogonTypeName(LogonSessionData->LogonType, szLogonType, _countof(szLogonType)), 
		LogonSessionData->Session, LogonSessionData->UserFlags,
		pszFlags,
		tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second,
		&SidString,
		&LogonSessionData->UserName,
		&LogonSessionData->LogonDomain,
		&LogonSessionData->DnsDomainName,
		&LogonSessionData->Upn,
		&LogonSessionData->LogonServer,
		&LogonSessionData->AuthenticationPackage);

	if (pszFlags && pszFlags != buf)
	{
		delete [] pszFlags;
	}

	RtlFreeUnicodeString(&SidString);
}

void PrintTime(_In_ PCSTR str, _In_ PLARGE_INTEGER Time)
{
	TIME_FIELDS tf;
	RtlTimeToTimeFields(Time, &tf);
	DbgPrint("@%s: %u-%02u-%02u %02u:%02u:%02u\r\n", str, tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second);
}

void PrintSid(PCSTR msg, PSID Sid)
{
	UNICODE_STRING str;
	if (0 <= RtlConvertSidToUnicodeString(&str, Sid, TRUE))
	{
		DbgPrint("@%s%wZ\r\n", msg, str);
		RtlFreeUnicodeString(&str);
	}
}

void Dump(PNETLOGON_VALIDATION_SAM_INFO4 pnvsi)
{
	CHAR buf[0x80];
	PSTR pszFlags = FormatUserFlags(pnvsi->UserFlags, buf, _countof(buf));
	DbgPrint("========NETLOGON_VALIDATION_SAM_INFO4:\r\n"
		"UserId=%u [C=%08x]\r\n"
		"\"%wZ\" | \"%wZ\"\r\n"
		"Server=\"%wZ\" Domain=\"%wZ\"\r\n"
		"GroupCount=%x PrimaryGroupId=[%u]\r\n"
		"UserFlags=%08X\r\n%s", 
		pnvsi->UserId, pnvsi->UserAccountControl, 
		&pnvsi->FullName, &pnvsi->EffectiveName,
		&pnvsi->LogonServer, &pnvsi->LogonDomainName,
		pnvsi->GroupCount, pnvsi->PrimaryGroupId,
		pnvsi->UserFlags, pszFlags);//

	if (pszFlags && pszFlags != buf)
	{
		delete [] pszFlags;
	}

	PrintTime("LogonTime", &pnvsi->LogonTime);

	if (ULONG GroupCount = pnvsi->GroupCount)
	{
		PGROUP_MEMBERSHIP GroupIds = pnvsi->GroupIds;
		do 
		{
			DbgPrint("\t%u [%x]\r\n", GroupIds->RelativeId, GroupIds->Attributes);
		} while (GroupIds++, --GroupCount);
	}

	PrintSid("LogonDomainId: ", pnvsi->LogonDomainId);

	DumpBytes("@UserSessionKey: ", pnvsi->UserSessionKey.data, 
		sizeof(pnvsi->UserSessionKey.data), CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF);

	if (ULONG SidCount = pnvsi->SidCount)
	{
		DbgPrint("@SidCount=%x\r\n", SidCount);
		PSID_AND_ATTRIBUTES ExtraSids = pnvsi->ExtraSids;
		do 
		{
			UNICODE_STRING us;
			if (0 <= RtlConvertSidToUnicodeString(&us, ExtraSids->Sid, TRUE))
			{
				DbgPrint("@\t[%wZ] [%08X]\r\n", &us, ExtraSids->Attributes);
				RtlFreeUnicodeString(&us);
			}
		} while (ExtraSids++, --SidCount);
	}

	DbgPrint("@DnsLogonDomainName=\"%wZ\"\r\nUpn=\"%wZ\"\r\n", pnvsi->DnsLogonDomainName, pnvsi->Upn);
}

void Print(_In_ PLSA_TOKEN_INFORMATION_V2 TokenInformation)
{
	if (PACL DefaultDacl = TokenInformation->DefaultDacl.DefaultDacl)
	{
		DbgPrint("DefaultDacl:\r\n");

		union {
			PVOID pv;
			PBYTE pb;
			PACE_HEADER pah;
			PACCESS_ALLOWED_ACE paaa;
			PSYSTEM_MANDATORY_LABEL_ACE psml;
		};

		if (ULONG AceCount = DefaultDacl->AceCount)
		{
			pv = DefaultDacl + 1;

			do 
			{
				switch (pah->AceType)
				{
				case ACCESS_ALLOWED_ACE_TYPE:
					DbgPrint("\t[%08X] ", paaa->Mask);
					PrintSid("ALLOWED TO: " , &paaa->SidStart);
					break;
				case ACCESS_DENIED_ACE_TYPE:
					DbgPrint("\t[%08X] ", paaa->Mask);
					PrintSid("DENIED TO: " , &paaa->SidStart);
					break;
				case SYSTEM_MANDATORY_LABEL_ACE_TYPE:
					DbgPrint("\t[%08X] ", psml->Mask);
					PrintSid("LABEL: " , &psml->SidStart);
					break;
				}

			} while (pb += pah->AceSize, --AceCount);
		}
	}

	PSID Sid;

	if (Sid = TokenInformation->Owner.Owner)
	{
		PrintSid("Owner: ", Sid);
	}

	if (Sid = TokenInformation->User.User.Sid)
	{
		PrintSid("User: ", Sid);
	}

	if (Sid = TokenInformation->PrimaryGroup.PrimaryGroup)
	{
		PrintSid("PrimaryGroup: ", Sid);
	}

	if (PTOKEN_GROUPS Groups = TokenInformation->Groups)
	{
		if (ULONG GroupCount = Groups->GroupCount)
		{
			DbgPrint("%u Groups:\r\n", GroupCount);
			PSID_AND_ATTRIBUTES rgGroups = Groups->Groups;
			do 
			{
				DbgPrint("\t[%08X] ", rgGroups->Attributes);
				PrintSid("", rgGroups++->Sid);
			} while (--GroupCount);
		}
	}

	if (PTOKEN_PRIVILEGES Privileges = TokenInformation->Privileges)
	{
		if (ULONG PrivilegeCount = Privileges->PrivilegeCount)
		{
			DbgPrint("%x Privileges:\r\n", PrivilegeCount);
			PLUID_AND_ATTRIBUTES rgPrivileges = Privileges->Privileges;
			do 
			{
				DbgPrint("\t[%08X] {%u}\r\n", rgPrivileges->Attributes, rgPrivileges->Luid.LowPart);
			} while (rgPrivileges++, --PrivilegeCount);
		}
	}
}

void Print(_In_ PSECPKG_PRIMARY_CRED PrimaryCredentials)
{
	DbgPrint("========SECPKG_PRIMARY_CRED:\r\n");
	if (PrimaryCredentials->UserSid)
	{
		PrintSid("UserSid      : ", PrimaryCredentials->UserSid);
	}

	DbgPrint(
		"@DownlevelName: \"%wZ\"\r\n"
		"DomainName   : \"%wZ\"\r\n"
		"DnsDomainName: \"%wZ\"\r\n"
		"LogonServer  : \"%wZ\"\r\n"
		"Upn          : \"%wZ\"\r\n"
		"Flags        : %08x\r\n",
		&PrimaryCredentials->DownlevelName,
		&PrimaryCredentials->DomainName,
		&PrimaryCredentials->DnsDomainName,
		&PrimaryCredentials->LogonServer,
		&PrimaryCredentials->Upn,
		PrimaryCredentials->Flags
		);
}
