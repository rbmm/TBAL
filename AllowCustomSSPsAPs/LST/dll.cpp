#include "stdafx.h"
#include "log.h"
#include "common.h"

BOOLEAN WINAPI DllMain( HMODULE hmod, DWORD ul_reason_for_call, PVOID pv)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hmod);
		LOG(Init());
		break;

	case DLL_PROCESS_DETACH:
		DbgPrint("exit(%p)\r\n", pv);
		LOG(Destroy());
		break;
	}

	return TRUE;
}

STDAPI DllRegisterServer()
{
	SECURITY_PACKAGE_OPTIONS spo = { sizeof(spo), SECPKG_OPTIONS_TYPE_UNKNOWN, /*SECPKG_OPTIONS_PERMANENT*/ };

	HRESULT hr = E_OUTOFMEMORY;

	if (PWSTR pszPackageName = new WCHAR[MINSHORT])
	{
		if (GetModuleFileNameW((HMODULE)&__ImageBase, pszPackageName, MINSHORT))
		{
			hr = AddSecurityPackageW(pszPackageName, &spo);
		}
		else
		{
			hr = GetLastError();
		}

		delete [] pszPackageName;
	}

	return hr;
}

EXTERN_C PVOID __imp_CredUIPromptForWindowsCredentialsW = 0;

HRESULT DumpCachedCredentialData(_In_ PBYTE pb, _In_ ULONG cb)
{
	DumpBytes("\r\nCachedCredentials:\r\n", pb, cb, CRYPT_STRING_HEXASCIIADDR);

	enum { min_size = (sizeof(NTLMSP_NAME) - sizeof(WCHAR)) + sizeof(ULONG) };

	if (cb < min_size) return 0;

	int n = (cb - min_size)/ sizeof(WCHAR);

	union  
	{
		PWSTR psz;
		PVOID pv;
	};

	pv = pb;
	PVOID pbEnd = pb + cb;

	do 
	{
		if (!memcmp(psz, NTLMSP_NAME, sizeof(NTLMSP_NAME) - sizeof(WCHAR)))
		{
			union  
			{
				PWSTR pwz;
				PULONG pu;
				PMSV1_0_SUPPLEMENTAL_CREDENTIAL psc;
				PMSV1_0_SUPPLEMENTAL_CREDENTIAL_V2 psc2;
				PMSV1_0_SUPPLEMENTAL_CREDENTIAL_V3 psc3;
				PMSV1_0_IUM_SUPPLEMENTAL_CREDENTIAL pium;
				PMSV1_0_REMOTE_SUPPLEMENTAL_CREDENTIAL prc;
			};

			pwz = psz + _countof(NTLMSP_NAME) - 1;

			ULONG CredentialSize = *pu++;

			if (CredentialSize <= RtlPointerToOffset(pu, pbEnd))
			{
				BOOL fOk;
				switch (pium->Version)
				{
				case MSV1_0_CRED_VERSION:
					if (fOk = sizeof(MSV1_0_SUPPLEMENTAL_CREDENTIAL) == CredentialSize)
					{
						DumpBytes("V1:", psc->NtPassword, MSV1_0_OWF_PASSWORD_LENGTH, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF);
					}
					break;

				case MSV1_0_CRED_VERSION_V2:
					if (fOk = sizeof(MSV1_0_SUPPLEMENTAL_CREDENTIAL_V2) == CredentialSize)
					{
						DumpBytes("V2:", psc2->NtPassword, MSV1_0_OWF_PASSWORD_LENGTH, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF);
						DumpBytes("Key:", psc2->CredentialKey.Data, MSV1_0_CREDENTIAL_KEY_LENGTH, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF);
					}
					break;

				case MSV1_0_CRED_VERSION_V3:
					if (fOk = sizeof(MSV1_0_SUPPLEMENTAL_CREDENTIAL_V3) == CredentialSize)
					{
						DumpBytes("V3:", psc3->NtPassword, MSV1_0_OWF_PASSWORD_LENGTH, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF);
						DumpBytes("Key:", psc3->CredentialKey.Data, MSV1_0_CREDENTIAL_KEY_LENGTH, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF);
						DumpBytes("SHA:", psc3->ShaPassword, MSV1_0_OWF_PASSWORD_LENGTH, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF);
					}

					break;
				
				case MSV1_0_CRED_VERSION_IUM:

					if (fOk = offsetof(MSV1_0_IUM_SUPPLEMENTAL_CREDENTIAL, EncryptedCreds) <= CredentialSize &&
						offsetof(MSV1_0_IUM_SUPPLEMENTAL_CREDENTIAL, EncryptedCreds[pium->EncryptedCredsSize]) == CredentialSize)
					{
						DbgPrint("MSV1_0_CRED_VERSION_IUM:\r\n");
					}
					break;

				case MSV1_0_CRED_VERSION_REMOTE:
					if (fOk = offsetof(MSV1_0_REMOTE_SUPPLEMENTAL_CREDENTIAL, EncryptedCreds) <= CredentialSize &&
						offsetof(MSV1_0_REMOTE_SUPPLEMENTAL_CREDENTIAL, EncryptedCreds[prc->EncryptedCredsSize]) == CredentialSize)
					{
						DbgPrint("MSV1_0_CRED_VERSION_REMOTE:\r\n");
					}
					break;

				default:
					fOk = FALSE;
				}

				if (fOk)
				{
					return S_OK;
				}
			}
		}

	} while (psz++, n--);

	return E_FAIL;
}

ULONG ErrorFromProtocolStatus(HRESULT status)
{
	if ((status & FACILITY_NT_BIT) || (0 > status && HRESULT_FACILITY(status) == FACILITY_NULL))
	{
		return RtlNtStatusToDosError(status & ~FACILITY_NT_BIT);
	}

	return status;
}

STDAPI DllInstall(BOOL bInstall, _In_opt_ PCWSTR pszCmdLine)
{
	if (!bInstall || !pszCmdLine)
	{
		return E_INVALIDARG;
	}

	NTSTATUS status = STATUS_NOT_SUPPORTED, ProtocolStatus = 0;
	
	if (!wcscmp(pszCmdLine, L"CacheLookup"))
	{
		if (HMODULE hmod = HR(status, LoadLibraryW(L"Credui.dll")))
		{
			if (__imp_CredUIPromptForWindowsCredentialsW = HR(status, GetProcAddress(hmod, "CredUIPromptForWindowsCredentialsW")))
			{
				LSA_HANDLE hLsa;
				if (0 <= (status = LsaConnectUntrusted(&hLsa)))
				{
					LSA_STRING PackageName;
					RtlInitString(&PackageName, "RBMM-LSA");
					ULONG ulAuthPackage, ulOutAuthBufferSize, cb = 0;
					PVOID pvOutAuthBuffer;

					if (0 <= (status = LsaLookupAuthenticationPackage(hLsa, &PackageName, &ulAuthPackage)))
					{
						CREDUI_INFO ci = { sizeof(ci), 0, 0, L"" };

						while (NOERROR == (status = CredUIPromptForWindowsCredentialsW(&ci, 
							ErrorFromProtocolStatus(ProtocolStatus), 
							&cb, 0, 0, &pvOutAuthBuffer, &ulOutAuthBufferSize, 0, 0)))
						{
							CustomRequest* req = (CustomRequest*)alloca(sizeof(CustomRequest) + ulOutAuthBufferSize);
							memcpy(req->buf, pvOutAuthBuffer, ulOutAuthBufferSize);

							CoTaskMemFree(pvOutAuthBuffer);

							req->ReqType = CustomRequest::tCacheLookup;

							PVOID pv = 0;

							status = LsaCallAuthenticationPackage(hLsa, ulAuthPackage, req, 
								sizeof(CustomRequest) + ulOutAuthBufferSize, &pv, &(cb = 0), &(ProtocolStatus = 0));

							DbgPrint("CallPackage = %x.%x [%x]\r\n", status, ProtocolStatus, cb);

							if (pv) 
							{
								if (0 <= ProtocolStatus && cb)
								{
									DumpCachedCredentialData((PBYTE)pv, cb);
								}

								LsaFreeReturnBuffer(pv);
							}

							if (!ProtocolStatus)
							{
								break;
							}
						}
					}

					LsaDeregisterLogonProcess(hLsa);
				}
			}

			FreeLibrary(hmod);
		}
	}

	return status;
}