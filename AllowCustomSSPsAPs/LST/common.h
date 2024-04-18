#pragma once

extern volatile const UCHAR guz;
extern ULONG_PTR _G_PackageId;
extern PLSA_SECPKG_FUNCTION_TABLE _G_FunctionTable;

#define LSA(...) _G_FunctionTable-> __VA_ARGS__

HRESULT GetLastErrorEx(ULONG dwError = GetLastError());

template <typename T> 
T HR(HRESULT& hr, T t)
{
	hr = t ? S_OK : GetLastErrorEx();
	return t;
}

inline ULONG BOOL_TO_ERROR(BOOL f)
{
	return f ? NOERROR : GetLastError();
}

#define _malloca_s(size) ((size) < _ALLOCA_S_THRESHOLD ? alloca(size) : new BYTE[size])

inline void _freea_s(PVOID pv)
{
	PNT_TIB tib = (PNT_TIB)NtCurrentTeb();
	if (pv < tib->StackLimit || tib->StackBase <= pv) delete [] pv;
}

typedef struct USER_SESSION_KEY {
	UCHAR data[16];
}* PUSER_SESSION_KEY;

typedef struct NETLOGON_VALIDATION_SAM_INFO4 {
	LARGE_INTEGER LogonTime;
	LARGE_INTEGER LogoffTime;
	LARGE_INTEGER KickOffTime;
	LARGE_INTEGER PasswordLastSet;
	LARGE_INTEGER PasswordCanChange;
	LARGE_INTEGER PasswordMustChange;
	UNICODE_STRING EffectiveName;
	UNICODE_STRING FullName;
	UNICODE_STRING LogonScript;
	UNICODE_STRING ProfilePath;
	UNICODE_STRING HomeDirectory;
	UNICODE_STRING HomeDirectoryDrive;
	USHORT LogonCount;
	USHORT BadPasswordCount;
	ULONG UserId;
	ULONG PrimaryGroupId;
	ULONG GroupCount;
	PGROUP_MEMBERSHIP GroupIds;
	ULONG UserFlags;
	USER_SESSION_KEY UserSessionKey;
	UNICODE_STRING LogonServer;
	UNICODE_STRING LogonDomainName;
	PSID LogonDomainId;
	UCHAR LMKey[8];
	ULONG UserAccountControl;
	ULONG SubAuthStatus;
	FILETIME LastSuccessfulILogon;
	FILETIME LastFailedILogon;
	ULONG FailedILogonCount;
	ULONG Reserved4;
	ULONG SidCount;
	PSID_AND_ATTRIBUTES ExtraSids;
	UNICODE_STRING DnsLogonDomainName;
	UNICODE_STRING Upn;
	UNICODE_STRING ExpansionString1;
	UNICODE_STRING ExpansionString2;
	UNICODE_STRING ExpansionString3;
	UNICODE_STRING ExpansionString4;
	UNICODE_STRING ExpansionString5;
	UNICODE_STRING ExpansionString6;
	UNICODE_STRING ExpansionString7;
	UNICODE_STRING ExpansionString8;
	UNICODE_STRING ExpansionString9;
	UNICODE_STRING ExpansionString10;
} *PNETLOGON_VALIDATION_SAM_INFO4;

//
// MsV1_0CacheLogon submit buffer
//

// Values for RequestFlags
#define MSV1_0_CACHE_LOGON_REQUEST_MIT_LOGON        0x00000001
#define MSV1_0_CACHE_LOGON_REQUEST_INFO4            0x00000002
#define MSV1_0_CACHE_LOGON_DELETE_ENTRY             0x00000004
#define MSV1_0_CACHE_LOGON_REQUEST_SMARTCARD_ONLY   0x00000008

typedef struct _MSV1_0_CACHE_LOGON_REQUEST {
	MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
	PVOID LogonInformation;
	PVOID ValidationInformation;
	PVOID SupplementalCacheData;
	ULONG SupplementalCacheDataLength;
	ULONG RequestFlags;
} MSV1_0_CACHE_LOGON_REQUEST, *PMSV1_0_CACHE_LOGON_REQUEST;

//
// MsV1_0CacheLookup submit buffer
//

// values for CredentialType
#define MSV1_0_CACHE_LOOKUP_CREDTYPE_NONE   0
#define MSV1_0_CACHE_LOOKUP_CREDTYPE_RAW    1
#define MSV1_0_CACHE_LOOKUP_CREDTYPE_NTOWF  2

template<ULONG n>
struct MSV1_0_CACHE_LOOKUP_REQUEST {
	MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
	UNICODE_STRING UserName;
	UNICODE_STRING DomainName;
	ULONG CredentialType;
	ULONG CredentialInfoLength;
	UCHAR CredentialSubmitBuffer[n];    // in-place array of length CredentialInfoLength
}; 

typedef struct _MSV1_0_CACHE_LOOKUP_RESPONSE {
	MSV1_0_PROTOCOL_MESSAGE_TYPE MessageType;
	PVOID ValidationInformation;
	PVOID SupplementalCacheData;
	ULONG SupplementalCacheDataLength;
} MSV1_0_CACHE_LOOKUP_RESPONSE, *PMSV1_0_CACHE_LOOKUP_RESPONSE;

HRESULT GetPublicKey(_In_ PCERT_INFO pCertInfo, _Out_ BCRYPT_KEY_HANDLE *phKey);

void Dump(PNETLOGON_VALIDATION_SAM_INFO4 pnvsi);

struct CLIENT_DATA 
{
	PLSA_CLIENT_REQUEST ClientRequest;
	PVOID *ProtocolReturnBuffer;
	PULONG ReturnBufferLength;

	CLIENT_DATA(_In_ PLSA_CLIENT_REQUEST ClientRequest,
		_Outptr_result_bytebuffer_(*ReturnBufferLength) PVOID *ProtocolReturnBuffer,
		_Out_ PULONG ReturnBufferLength) : ClientRequest(ClientRequest), 
		ProtocolReturnBuffer(ProtocolReturnBuffer), ReturnBufferLength(ReturnBufferLength)
	{
	}

	NTSTATUS CopyToClient(_In_ PVOID pv, _In_ ULONG cb);

	HRESULT CacheLookup(
		_In_ PVOID ProtocolSubmitBuffer, 
		_In_ ULONG SubmitBufferSize,
		_In_ PVOID ClientBufferBase);

	HRESULT CacheLookup(
		_In_ PCWSTR pszPin,
		_In_ PUCHAR rgbHashOfCert,
		_In_opt_ PCWSTR CSPName,
		_In_ PCWSTR ReaderName, 
		_In_ PCWSTR ContainerName, 
		_In_ ULONG dwLegacyKeySpec);

	HRESULT CacheLookup(
		_In_ PCCERT_CONTEXT pCertContext, 
		_In_ NCRYPT_KEY_HANDLE hKey, 
		_In_ PCWSTR pszPin);
};

struct CustomRequest 
{
	union {
		ULONG64 align;
		enum { tCacheLookup = 'chlk' } ReqType;
	};

	UCHAR buf[];
};

C_ASSERT(sizeof(CustomRequest)==sizeof(ULONG64));
