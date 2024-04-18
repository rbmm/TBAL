#include "stdafx.h"

#include "log.h"
#include "common.h"

HRESULT GetLastErrorEx(ULONG dwError /*= GetLastError()*/)
{
	NTSTATUS status = RtlGetLastNtStatus();
	return RtlNtStatusToDosErrorNoTeb(status) == dwError ? HRESULT_FROM_NT(status) : HRESULT_FROM_WIN32(dwError);
}

inline HRESULT HRESULT_FROM_SSPI(HRESULT hr)
{
	return 0 < hr ? (0x80000000 | (FACILITY_SSPI << 16) | (hr & MAXUSHORT)) : hr;
}

HRESULT ValidateCert(_In_ PCCERT_CONTEXT pCertContext)
{
	PCCERT_CHAIN_CONTEXT pChainContext = 0;

	static const PCSTR szUsageIdentifier = szOID_KP_SMARTCARD_LOGON;

	CERT_CHAIN_PARA ChainPara = { 
		sizeof(ChainPara), { USAGE_MATCH_TYPE_AND, { 1, const_cast<PSTR*>(&szUsageIdentifier) } } 
	};

	HRESULT hr;
	//CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY|

	if (HR(hr, CertGetCertificateChain(HCCE_LOCAL_MACHINE, pCertContext, 0, 0, &ChainPara, 
		CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, 0, &pChainContext)))
	{
		DbgPrint("CERT_TRUST_STATUS = { E=%x, I=%x }\r\n", pChainContext->TrustStatus.dwErrorStatus, pChainContext->TrustStatus.dwInfoStatus);

		CERT_CHAIN_POLICY_PARA PolicyPara = { sizeof(PolicyPara), CERT_CHAIN_POLICY_IGNORE_ALL_REV_UNKNOWN_FLAGS };
		CERT_CHAIN_POLICY_STATUS PolicyStatus = { sizeof(PolicyStatus) };
		if (HR(hr, CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_NT_AUTH, pChainContext, &PolicyPara, &PolicyStatus)))
		{
			hr = PolicyStatus.dwError;
		}

		CertFreeCertificateChain(pChainContext);
	}

	DbgPrint("VerifyCertificate=%x\r\n", hr);

	return HRESULT_FROM_WIN32(hr);
}

HRESULT GetPublicKey(_In_ PCERT_INFO pCertInfo, _Out_ BCRYPT_KEY_HANDLE *phKey)
{
	return CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &pCertInfo->SubjectPublicKeyInfo, 0, 0, phKey) ? S_OK : GetLastErrorEx();
}

HRESULT GetKspCert(_In_ NCRYPT_KEY_HANDLE hKey, _Out_ PCCERT_CONTEXT* ppCertContext)
{
	HRESULT status;
	ULONG cbCertEncoded = 0;
	PUCHAR pbCertEncoded = 0;

	while (S_OK == (status = NCryptGetProperty(hKey, NCRYPT_CERTIFICATE_PROPERTY, pbCertEncoded, cbCertEncoded, &cbCertEncoded, 0)))
	{
		if (pbCertEncoded)
		{
			if (PCCERT_CONTEXT pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, pbCertEncoded, cbCertEncoded))
			{
				*ppCertContext = pCertContext;
			}
			else
			{
				status = GetLastError();
			}

			break;
		}

		if (!(pbCertEncoded = (PBYTE)_malloca_s(cbCertEncoded)))
		{
			status = NTE_NO_MEMORY;
			break;
		}
	}

	if (pbCertEncoded)
	{
		_freea_s(pbCertEncoded);
	}

	DbgPrint("GetKspCert=%x\r\n", status);

	return HRESULT_FROM_WIN32(status);
}

HRESULT OpenKspKey(_Out_ NCRYPT_KEY_HANDLE* phKey, 
				   _In_ PCWSTR pszProviderName,
				   _In_ PWSTR pszKeyName, 
				   _In_ ULONG dwLegacyKeySpec)
{
	NCRYPT_PROV_HANDLE hProvider;

	NTSTATUS hr = NCryptOpenStorageProvider(&hProvider, pszProviderName, 0);

	DbgPrint("OpenProvider(\"%S\")=%x\r\n", pszProviderName, hr);

	if (hr == NOERROR)
	{
		hr = NCryptOpenKey(hProvider, phKey, pszKeyName, dwLegacyKeySpec, NCRYPT_SILENT_FLAG);

		NCryptFreeObject(hProvider);

		DbgPrint("OpenKey(%x \"%S\")=%x\r\n", dwLegacyKeySpec, pszKeyName, hr);
	}

	return HRESULT_FROM_SSPI(hr);
}

HRESULT OpenKspKey(_Out_ NCRYPT_KEY_HANDLE* phKey, 
				   _In_ PCWSTR pszProviderName,
				   _In_ PCWSTR ReaderName, 
				   _In_ PCWSTR ContainerName, 
				   _In_ ULONG dwLegacyKeySpec)
{
	PWSTR pszKeyName = 0;
	int len = 0;

	while (0 < (len = _snwprintf(pszKeyName, len, L"\\\\.\\%s\\%s", ReaderName, ContainerName)))
	{
		if (pszKeyName)
		{
			return OpenKspKey(phKey, pszProviderName, pszKeyName, dwLegacyKeySpec);
		}

		pszKeyName = (PWSTR)alloca(++len * sizeof(WCHAR));
	}

	return STATUS_INTERNAL_ERROR;
}

HRESULT OpenKspKey(_Out_ NCRYPT_KEY_HANDLE* phKey, _In_ PUCHAR rgbHashOfCert)
{
	HRESULT hr;

	if (HCERTSTORE hCertStore = HR(hr, CertOpenStore(CERT_STORE_PROV_SYSTEM, X509_ASN_ENCODING, 0, 
		CERT_SYSTEM_STORE_CURRENT_USER|CERT_STORE_OPEN_EXISTING_FLAG|CERT_STORE_READONLY_FLAG, L"MY")))
	{
		DumpBytes("CertHash: ", rgbHashOfCert, CERT_HASH_LENGTH, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF);

		CRYPT_HASH_BLOB sha1 = { CERT_HASH_LENGTH, rgbHashOfCert };

		if (PCCERT_CONTEXT pCertContext = HR(hr, CertFindCertificateInStore(hCertStore, X509_ASN_ENCODING, 0, CERT_FIND_SHA1_HASH, &sha1, 0)))
		{
			ULONG cb = 0;
			PCRYPT_KEY_PROV_INFO pckpi = 0;

			while(HR(hr, CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, pckpi, &cb)))
			{
				if (pckpi)
				{
					hr = OpenKspKey(phKey, pckpi->pwszProvName, pckpi->pwszContainerName, pckpi->dwKeySpec);
					break;
				}

				pckpi = (PCRYPT_KEY_PROV_INFO)alloca(cb);
			}

			CertFreeCertificateContext(pCertContext);
		}

		CertCloseStore(hCertStore, 0);

	}

	return HRESULT_FROM_WIN32(hr);
}

HRESULT CheckPin(_In_ PCCERT_CONTEXT pCertContext, _In_ NCRYPT_KEY_HANDLE hNKey, _In_ PCWSTR pszPin)
{
	UCHAR hash[32];
	NTSTATUS status = BCryptGenRandom(0, hash, sizeof(hash), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

	if (0 <= status)
	{
		BCRYPT_KEY_HANDLE hBKey;

		if (S_OK == (status = GetPublicKey(pCertContext->pCertInfo, &hBKey)))
		{
			status = NCryptSetProperty(hNKey, NCRYPT_PIN_PROPERTY, (PBYTE)pszPin, sizeof(WCHAR)*(1 + (ULONG)wcslen(pszPin)), 0);

			DbgPrint("NCRYPT_PIN_PROPERTY=%x\r\n", status);

			if (S_OK == status)
			{
				BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA256_ALGORITHM };
				PBYTE pbSignature = 0;
				ULONG cbSignature = 0;

				while (S_OK == (status = NCryptSignHash(hNKey, &pi, hash, sizeof(hash), 
					pbSignature, cbSignature, &cbSignature, BCRYPT_PAD_PKCS1)))
				{
					if (pbSignature)
					{
						status = BCryptVerifySignature(hBKey, &pi, hash, 
							sizeof(hash), pbSignature, cbSignature, BCRYPT_PAD_PKCS1);

						break;
					}

					pbSignature = (PUCHAR)alloca(cbSignature);
				}

				DbgPrint("Sign/Verify=%x\r\n", status);
			}
			else
			{
				status = SCARD_W_WRONG_CHV;
			}

			BCryptDestroyKey(hBKey);
		}
	}

	return status;
}

HRESULT CheckCertHash(_In_ PCCERT_CONTEXT pCertContext, _In_ PUCHAR rgbHashOfCert)
{
	UCHAR hash[CERT_HASH_LENGTH];
	ULONG cb = sizeof(hash);

	if (!CryptHashCertificate2(BCRYPT_SHA1_ALGORITHM, 0, 0, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, hash, &cb))
	{
		return GetLastErrorEx();
	}

	if (cb != CERT_HASH_LENGTH || memcmp(rgbHashOfCert, hash, CERT_HASH_LENGTH))
	{
		DumpBytes("!! CertHash: ", hash, cb, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF);
		return NTE_NOT_FOUND;
	}

	return S_OK;
}

HRESULT CLIENT_DATA::CacheLookup(_In_ PCWSTR pszPin,
								 _In_ PUCHAR rgbHashOfCert,
								 _In_opt_ PCWSTR CSPName,
								 _In_ PCWSTR ReaderName, 
								 _In_ PCWSTR ContainerName, 
								 _In_ ULONG dwLegacyKeySpec)
{
	HRESULT hr;
	NCRYPT_KEY_HANDLE hKey;

	if (0 <= (hr = CSPName ? OpenKspKey(&hKey, CSPName, ReaderName, ContainerName, dwLegacyKeySpec) : OpenKspKey(&hKey, rgbHashOfCert)))
	{
		PCCERT_CONTEXT pCertContext;

		if (0 <= (hr = GetKspCert(hKey, &pCertContext)))
		{
			if (0 <= (hr = CSPName ? S_OK : CheckCertHash(pCertContext, rgbHashOfCert)) &&
				0 <= (hr = ValidateCert(pCertContext)) && 
				0 <= (hr = CheckPin(pCertContext, hKey, pszPin)))
			{
				CacheLookup(pCertContext, hKey, pszPin);
			}

			CertFreeCertificateContext(pCertContext);
		}

		NCryptFreeObject(hKey);
	}

	return hr;
}
