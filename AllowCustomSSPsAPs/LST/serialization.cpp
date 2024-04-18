#include "stdafx.h"

#include "log.h"
#include "common.h"

typedef struct KERB_SMARTCARD_CSP_INFO
{   
	ULONG dwCspInfoLen;				// size of this structure w/ payload
	ULONG MessageType;				// info type, currently CertHashInfo
	// payload starts, marshaled structure of MessageType
	union {     
		PVOID ContextInformation;	// Reserved
		ULONG64 SpaceHolderForWow64; 
	}; 
	ULONG flags;					// Reserved
	ULONG KeySpec;					// AT_SIGNATURE xor AT_KEYEXCHANGE
	ULONG nCardNameOffset; 
	ULONG nReaderNameOffset; 
	ULONG nContainerNameOffset; 
	ULONG nCSPNameOffset; 
	WCHAR Buffer[];
} *PKERB_SMARTCARD_CSP_INFO;

BOOLEAN IsDataOk(ULONG_PTR m, ULONG_PTR M, ULONG_PTR rva, ULONG size = 1, 
				 ULONG_PTR type_align = 0, ULONG_PTR size_align = 0, ULONG_PTR min_size = 0)
{
	if ((rva & type_align) || (size & size_align) || size < min_size || rva < m)
	{
		return FALSE;
	}

	ULONG_PTR end = rva + size;

	return rva < end && end <= M;
}

BOOLEAN UserNameToCertHash(_In_ PCWSTR pszUserName,
						   _Out_writes_bytes_opt_(CERT_HASH_LENGTH) PUCHAR rgbHashOfCert)
{
	CRED_MARSHAL_TYPE CredType;

	union {
		PVOID Credential;
		PCERT_CREDENTIAL_INFO pCertCredInfo;
	};

	if (CredUnmarshalCredential(pszUserName, &CredType, &Credential))
	{
		if (CredType == CertCredential && pCertCredInfo->cbSize >= sizeof(CERT_CREDENTIAL_INFO))
		{
			memcpy(rgbHashOfCert, pCertCredInfo->rgbHashOfCert, CERT_HASH_LENGTH);
			pszUserName = 0;
		}

		CredFree(Credential);

		if (!pszUserName)
		{
			return TRUE;
		}
	}

	return FALSE;
}

BOOLEAN Validate(_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer, 
				 _In_ ULONG SubmitBufferSize,
				 _In_ PVOID ClientBufferBase,
				 _Out_ PUNICODE_STRING Pin,
				 _Out_ ULONG* KeySpec,
				 _Out_ PCWSTR* CardName,
				 _Out_ PCWSTR* ReaderName,
				 _Out_ PCWSTR* ContainerName,
				 _Out_ PCWSTR* CSPName,
				 _Out_writes_bytes_opt_(CERT_HASH_LENGTH) PUCHAR rgbHashOfCert)
{
	if (SubmitBufferSize <= sizeof(KERB_LOGON_SUBMIT_TYPE))
	{
		return FALSE;
	}

	union {
		PVOID pv;
		ULONG_PTR up;

		PKERB_LOGON_SUBMIT_TYPE pMessageType;

		PKERB_CERTIFICATE_LOGON pCertLogon;
		PKERB_CERTIFICATE_UNLOCK_LOGON pCertUnlockLogon;

		PKERB_SMART_CARD_LOGON pScLogon;
		PKERB_SMART_CARD_UNLOCK_LOGON pScUnlockLogon;

		PKERB_INTERACTIVE_LOGON pIntLogon;
		PKERB_INTERACTIVE_UNLOCK_LOGON pIntUnlockLogon;

		PUCHAR CspData;						// contains the smartcard CSP data
		PKERB_SMARTCARD_CSP_INFO pksci;
	};

	pv = ProtocolSubmitBuffer;

	ULONG_PTR offset;

	ULONG Length, CspDataLength, StructSize = 0;

	DbgPrint("MessageType = %x\r\n", *pMessageType);

	switch (*pMessageType)
	{
	case KerbCertificateUnlockLogon:
		StructSize = sizeof(LUID);
		[[fallthrough]];
	case KerbCertificateLogon:
		if (SubmitBufferSize <= (StructSize += sizeof(KERB_CERTIFICATE_LOGON)))
		{
			return FALSE;
		}
		*Pin = pCertLogon->Pin;
		CspDataLength = pCertLogon->CspDataLength;
		CspData = pCertLogon->CspData;
		break;

	case KerbSmartCardUnlockLogon:
		StructSize = sizeof(LUID);
		[[fallthrough]];
	case KerbSmartCardLogon:
		if (SubmitBufferSize <= (StructSize += sizeof(PKERB_SMART_CARD_LOGON)))
		{
			return FALSE;
		}
		*Pin = pScLogon->Pin;
		CspDataLength = pScLogon->CspDataLength;
		CspData = pScLogon->CspData;
		break;

	case KerbWorkstationUnlockLogon:
		StructSize = sizeof(LUID);
		[[fallthrough]];
	case KerbInteractiveLogon:
		if (SubmitBufferSize <= (StructSize += sizeof(KERB_INTERACTIVE_LOGON)))
		{
			return FALSE;
		}
		*Pin = pIntLogon->Password;

		UNICODE_STRING UserName = pIntLogon->UserName, UserName0;

		if ((offset = (ULONG_PTR)Pin->Buffer - (ULONG_PTR)ClientBufferBase) < SubmitBufferSize)
		{
			Pin->Buffer = (PWSTR)offset;
		}

		if ((offset = (ULONG_PTR)UserName.Buffer - (ULONG_PTR)ClientBufferBase) < SubmitBufferSize)
		{
			UserName.Buffer = (PWSTR)offset;
		}

		if ((Length = Pin->Length) > Pin->MaximumLength || !IsDataOk(StructSize, SubmitBufferSize, 
			(ULONG_PTR)Pin->Buffer, Length, __alignof(WCHAR) - 1, __alignof(WCHAR) - 1, sizeof(WCHAR)))
		{
			return FALSE;
		}

		(ULONG_PTR&)Pin->Buffer += (ULONG_PTR)ProtocolSubmitBuffer;

		if ((Length = UserName.Length) > UserName.MaximumLength || !IsDataOk(StructSize, SubmitBufferSize, 
			(ULONG_PTR)UserName.Buffer, Length, __alignof(WCHAR) - 1, __alignof(WCHAR) - 1, sizeof(WCHAR)))
		{
			return FALSE;
		}

		(ULONG_PTR&)UserName.Buffer += (ULONG_PTR)ProtocolSubmitBuffer;

		*CSPName = 0;

		if (0 <= RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE, &UserName, &UserName0))
		{
			if (UserNameToCertHash(UserName0.Buffer, rgbHashOfCert))
			{
				CSPName = 0;
			}
			RtlFreeUnicodeString(&UserName0);
		}

		return CSPName == 0;

	default: 
		return FALSE;
	}

	if ((offset = (ULONG_PTR)CspData - (ULONG_PTR)ClientBufferBase) < SubmitBufferSize)
	{
		up = offset;
	}

	if ((offset = (ULONG_PTR)Pin->Buffer - (ULONG_PTR)ClientBufferBase) < SubmitBufferSize)
	{
		Pin->Buffer = (PWSTR)offset;
	}

	if (!IsDataOk(StructSize, SubmitBufferSize, up, CspDataLength, 
		__alignof(KERB_SMARTCARD_CSP_INFO) - 1, 0, sizeof(KERB_SMARTCARD_CSP_INFO)))
	{
		return FALSE;
	}

	if ((Length = Pin->Length) > Pin->MaximumLength || !IsDataOk(StructSize, up, (ULONG_PTR)Pin->Buffer, Length, 
		__alignof(WCHAR) - 1, __alignof(WCHAR) - 1, sizeof(WCHAR)))
	{
		return FALSE;
	}

	(ULONG_PTR&)Pin->Buffer += (ULONG_PTR)ProtocolSubmitBuffer, up += (ULONG_PTR)ProtocolSubmitBuffer;

	ULONG dwCspInfoLen = pksci->dwCspInfoLen;

	if (dwCspInfoLen <= sizeof(KERB_SMARTCARD_CSP_INFO ) || dwCspInfoLen > CspDataLength)
	{
		return FALSE;
	}

	dwCspInfoLen -= sizeof(KERB_SMARTCARD_CSP_INFO );

	if (!(dwCspInfoLen /= sizeof(WCHAR)) || pksci->Buffer[dwCspInfoLen - 1])
	{
		return FALSE;
	}

	ULONG nCardNameOffset, nReaderNameOffset, nContainerNameOffset, nCSPNameOffset;

	if (!IsDataOk(0, dwCspInfoLen, nCardNameOffset = pksci->nCardNameOffset) ||
		!IsDataOk(0, dwCspInfoLen, nReaderNameOffset = pksci->nReaderNameOffset) ||
		!IsDataOk(0, dwCspInfoLen, nContainerNameOffset = pksci->nContainerNameOffset) ||
		!IsDataOk(0, dwCspInfoLen, nCSPNameOffset = pksci->nCSPNameOffset))
	{
		return FALSE;
	}

	*CardName = &pksci->Buffer[nCardNameOffset];
	*ContainerName = &pksci->Buffer[nContainerNameOffset];
	*CSPName = &pksci->Buffer[nCSPNameOffset];
	*ReaderName = &pksci->Buffer[nReaderNameOffset];
	*KeySpec = pksci->KeySpec;

	return TRUE;
}

HRESULT DecryptPin(_In_ PWSTR pszCredentials, _In_ ULONG cchCredentials, _Out_ PWSTR* ppszPin)
{
	ULONG cchPin = 0;
	PWSTR pszPin = 0;

	HRESULT status;

	while (ERROR_INSUFFICIENT_BUFFER == (status = BOOL_TO_ERROR(CredUnprotectW(
		FALSE, pszCredentials, cchCredentials, pszPin, &cchPin))))
	{
		if (pszPin || !(pszPin = new WCHAR[cchPin + 1]))
		{
			status = E_OUTOFMEMORY;
			break;
		}
	}

	if (NOERROR == status)
	{
		pszPin[cchPin] = 0;
		*ppszPin = pszPin;
	}

	return HRESULT_FROM_WIN32(status);
}

NTSTATUS RtlRevertToSelf()
{
	HANDLE hToken = 0;
	return NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
}

HRESULT CLIENT_DATA::CacheLookup(_In_ PVOID ProtocolSubmitBuffer, 
								 _In_ ULONG SubmitBufferSize,
								 _In_ PVOID ClientBufferBase)
{
	UNICODE_STRING Pin;
	ULONG KeySpec;
	PCWSTR CardName, ReaderName, ContainerName, CSPName;
	UCHAR rgbHashOfCert[CERT_HASH_LENGTH];

	if (!Validate(ProtocolSubmitBuffer, SubmitBufferSize, ClientBufferBase, 
		&Pin, &KeySpec, &CardName, &ReaderName, &ContainerName, &CSPName, rgbHashOfCert))
	{
		DumpBytes("!! Invalid Submit Buffer\r\n", (PBYTE)ProtocolSubmitBuffer, SubmitBufferSize, CRYPT_STRING_HEXASCIIADDR);
		return NTE_INVALID_PARAMETER;
	}

	HRESULT hr = LSA(ImpersonateClient());

	if (0 <= hr)
	{
		if (S_OK == (hr = DecryptPin(Pin.Buffer, Pin.Length / sizeof(WCHAR), &Pin.Buffer)))
		{
			DbgPrint("Pin = \"%S\"\r\n", Pin.Buffer);

			hr = CacheLookup(Pin.Buffer, rgbHashOfCert, CSPName, ReaderName, ContainerName, KeySpec);

			delete [] Pin.Buffer;
		}

		RtlRevertToSelf();
	}

	DbgPrint("GetUserCert=%x\r\n", hr);

	return hr;
}