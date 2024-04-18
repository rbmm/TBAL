#include "stdafx.h"

#include "log.h"
#include "common.h"

ULONG_PTR _G_PackageId = 0;
PLSA_SECPKG_FUNCTION_TABLE _G_FunctionTable = 0;

volatile const UCHAR guz = 0;

NTSTATUS CLIENT_DATA::CopyToClient(_In_ PVOID pv, _In_ ULONG cb)
{
	NTSTATUS status;
	PVOID ClientBaseAddress;
	if (0 <= (status = LSA(AllocateClientBuffer(ClientRequest, cb, &ClientBaseAddress))))
	{
		if (0 > (status = LSA(CopyToClientBuffer(ClientRequest, cb, ClientBaseAddress, pv))))
		{
			LSA(FreeClientBuffer(ClientRequest, ClientBaseAddress));
		}
		else
		{
			*ProtocolReturnBuffer = ClientBaseAddress;
			*ReturnBufferLength = cb;
		}
	}

	return status;
}

NTSTATUS NTAPI CallPackage (
							_In_ PLSA_CLIENT_REQUEST ClientRequest,
							_In_reads_bytes_(SubmitBufferLength) PVOID ProtocolSubmitBuffer,
							_In_ PVOID ClientBufferBase,
							_In_ ULONG SubmitBufferLength,
							_Outptr_result_bytebuffer_(*ReturnBufferLength) PVOID *ProtocolReturnBuffer,
							_Out_ PULONG ReturnBufferLength,
							_Out_ PNTSTATUS ProtocolStatus
							)
{
	*ProtocolReturnBuffer = 0, *ReturnBufferLength = 0;

	if (SubmitBufferLength)
	{
		DumpBytes("\r\n\r\nCallPackage:\r\n", (PBYTE)ProtocolSubmitBuffer, SubmitBufferLength, CRYPT_STRING_HEXASCIIADDR);
	}

	NTSTATUS status;

	if (SubmitBufferLength < sizeof(CustomRequest))
	{
		status = STATUS_BUFFER_TOO_SMALL;
	}
	else
	{
		ULONG ReqType = reinterpret_cast<CustomRequest*>(ProtocolSubmitBuffer)->ReqType;

		(PBYTE&)ClientBufferBase += sizeof(CustomRequest);
		(PBYTE&)ProtocolSubmitBuffer += sizeof(CustomRequest);
		SubmitBufferLength -= sizeof(CustomRequest);

		CLIENT_DATA cd(ClientRequest, ProtocolReturnBuffer, ReturnBufferLength);
		
		switch (ReqType)
		{
		case CustomRequest::tCacheLookup:
			status = cd.CacheLookup(ProtocolSubmitBuffer, SubmitBufferLength, ClientBufferBase);
			break;
		default:
			status = STATUS_NOT_IMPLEMENTED;
		}
	}

	*ProtocolStatus = status;

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI SpShutdown()
{
	DbgPrint("SpShutdown\r\n");
	return STATUS_SUCCESS; 
}

NTSTATUS NTAPI SpGetInfo(_Out_ PSecPkgInfoW PackageInfo)
{
	DbgPrint("SpGetInfo\r\n");
	PackageInfo->fCapabilities = SECPKG_FLAG_LOGON;
	PackageInfo->wVersion = SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION;
	PackageInfo->wRPCID = RPC_C_AUTHN_NONE;
	PackageInfo->Name = const_cast<PWSTR>(L"RBMM-LSA");
	PackageInfo->Comment = 0;
	PackageInfo->cbMaxToken = 0;

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI Initialize(
						  _In_ ULONG_PTR PackageId,
						  _In_ PSECPKG_PARAMETERS Parameters,
						  _In_ PLSA_SECPKG_FUNCTION_TABLE FunctionTable
						  )
{
	_G_PackageId = PackageId;
	_G_FunctionTable = FunctionTable;

	DbgPrint("Initialize([%x, %x, %x] \"%wZ\" \"%wZ\")\r\n", 
		Parameters->Version, Parameters->MachineState, Parameters->SetupMode,
		&Parameters->DomainName, &Parameters->DnsDomainName);

	return STATUS_SUCCESS;
}

const SECPKG_FUNCTION_TABLE g_Table = { 
	0, 
	0, 
	CallPackage, 
	0, 
	CallPackage, 
	CallPackage, 
	0, 
	0, //LogonUserEx2, 
	Initialize, 
	SpShutdown, 
	SpGetInfo,
	0, 
	0,//SpAcquireCredentialsHandle, 
	0, 
	0,//SpFreeCredentialsHandle, 
	0, 
	0, 
	0, 
	0,//SpInitLsaModeContext, 
	0,//SpAcceptLsaModeContext, 
	0,//SpDeleteContext, 
	0, 
	0, 
	0,//SpGetExtendedInformation, 
	0,//SpQueryContextAttributes, 
	0, 
	0,//SpSetExtendedInformation, 
	0, 
	0, 
	0, 
	0,//SpQueryMetaData, 
	0,//SpExchangeMetaData, 
};

BOOL IsSafeBoot()
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	RtlInitUnicodeString(&ObjectName, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Option");

	HANDLE hKey;
	if (0 <= ZwOpenKey(&hKey, KEY_READ, &oa))
	{
		ULONG cb;
		KEY_VALUE_PARTIAL_INFORMATION_ALIGN64 kvpi;
		RtlInitUnicodeString(&ObjectName, L"OptionValue");

		NTSTATUS status = ZwQueryValueKey(hKey, &ObjectName, KeyValuePartialInformationAlign64, &kvpi, sizeof(kvpi), &cb);
		NtClose(hKey);

		return 0 <= status && REG_DWORD == kvpi.Type && kvpi.DataLength == sizeof(ULONG) && *(ULONG*)kvpi.Data;
	}

	return FALSE;
}

NTSTATUS NTAPI SpLsaModeInitialize(
								   __in   ULONG LsaVersion,
								   __out  PULONG PackageVersion,
								   __out  PSECPKG_FUNCTION_TABLE* ppTables,
								   __out  PULONG pcTables
								   )
{
	DbgPrint("SpLsaModeInitialize(%x)\r\n", LsaVersion);
	*PackageVersion = SECPKG_INTERFACE_VERSION_10;
	*ppTables = const_cast<PSECPKG_FUNCTION_TABLE>(&g_Table);
	*pcTables = 1;
	// The driver was not loaded because the system is booting into safe mode.
	return IsSafeBoot() ? STATUS_NOT_SAFE_MODE_DRIVER : STATUS_SUCCESS;
}
