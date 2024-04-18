#include "stdafx.h"
#include "log.h"
#include "common.h"

void reverse(PBYTE pb, size_t cb )
{
	if (cb)
	{
		PBYTE qb = pb + cb;

		do 
		{
			BYTE b = *--qb;
			*qb = *pb;
			*pb++ = b;
		} while (pb < qb);
	}
}

NTSTATUS CreateSymKey(_Out_ BCRYPT_KEY_HANDLE* phKey, _In_ PCWSTR pszAlgId, _In_ PUCHAR pbSecret, _In_ ULONG cbSecret)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;

	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0)))
	{
		status = BCryptGenerateSymmetricKey(hAlgorithm, phKey, 0, 0, pbSecret, cbSecret, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

NTSTATUS CreateHash(_Out_ BCRYPT_HASH_HANDLE *phHash, _In_ PCWSTR pszAlgId)
{
	NTSTATUS status;
	BCRYPT_ALG_HANDLE hAlgorithm;

	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 0)))
	{
		status = BCryptCreateHash(hAlgorithm, phHash, 0, 0, 0, 0, 0);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	}

	return status;
}

NTSTATUS DoHash(_In_ PCWSTR pszAlgId, _In_ PDATA_BLOB pdb, _In_ ULONG n, _Out_ PUCHAR pbOutput, _In_ ULONG cbOutput)
{
	NTSTATUS status;
	BCRYPT_HASH_HANDLE hHash;

	if (0 <= (status = CreateHash(&hHash, pszAlgId)))
	{
		do; while (0 <= (status = BCryptHashData(hHash, pdb->pbData, pdb->cbData, 0)) && (pdb++, --n));

		if (0 <= status)
		{
			status = BCryptFinishHash(hHash, pbOutput, cbOutput, 0);
		}

		BCryptDestroyHash(hHash);
	}

	return status;
}

NTSTATUS DoHash(_In_ PCWSTR pszAlgId, _In_ const BYTE* pbData, _In_ ULONG cbData, _Out_ PUCHAR pbOutput, _In_ ULONG cbOutput)
{
	DATA_BLOB db = { cbData, const_cast<PBYTE>(pbData) };
	return DoHash(pszAlgId, &db, 1, pbOutput, cbOutput);
}

NTSTATUS Hmac(_In_ PCWSTR pszAlgId,
			  _In_ PUCHAR pbSecret,
			  _In_ ULONG cbSecret,
			  _In_ PUCHAR pbInput, 
			  _In_ ULONG cbInput, 
			  _Out_ PBYTE pbHash, 
			  _In_ ULONG cbHash)
{
	BCRYPT_ALG_HANDLE hAlgorithm;

	NTSTATUS status;
	if (0 <= (status = BCryptOpenAlgorithmProvider(&hAlgorithm, pszAlgId, 0, 
		BCRYPT_ALG_HANDLE_HMAC_FLAG|BCRYPT_HASH_REUSABLE_FLAG)))
	{
		BCRYPT_HASH_HANDLE hHash;

		status = BCryptCreateHash(hAlgorithm, &hHash, 0, 0, pbSecret, cbSecret, BCRYPT_HASH_REUSABLE_FLAG);

		BCryptCloseAlgorithmProvider(hAlgorithm, 0);

		if (0 <= status)
		{
			0 <= (status = BCryptHashData(hHash, pbInput, cbInput, 0)) &&
				0 <= (status = BCryptFinishHash(hHash, pbHash, cbHash, 0));

			BCryptDestroyHash(hHash);
		}
	}

	return status;
}

struct ScHelper_RandomCredBits
{
	BYTE _M_bR1[32];
	BYTE _M_bR2[32];
};

struct HMAC 
{
	ULONG _M_dwHmacSize;
	UCHAR _M_bHmac[CERT_HASH_LENGTH];
};

struct KERB_SUPP_CREDS : ScHelper_RandomCredBits
{
	union {
		UCHAR _M_bEncrypted[];
		struct {
			HMAC _M_Hmac;
			UCHAR _M_bCacheData[];
		};
	};

	HRESULT DecryptCredentials(
		_In_ PCERT_INFO pCertInfo, 
		_In_ NCRYPT_KEY_HANDLE hKey, 
		_In_ PCWSTR pszPin, 
		_In_ ULONG cbCacheData,
		_Out_ PVOID *ppv,
		_Out_ ULONG *pcb);
};

C_ASSERT(sizeof(KERB_SUPP_CREDS)==32+32+4+20);

HRESULT KERB_SUPP_CREDS::DecryptCredentials(
	_In_ PCERT_INFO pCertInfo, 
	_In_ NCRYPT_KEY_HANDLE hKey, 
	_In_ PCWSTR pszPin, 
	_In_ ULONG cbCacheData,
	_Out_ PVOID *ppv,
	_Out_ ULONG *pcb)
{
	HRESULT hr;
	UCHAR sha1[CERT_HASH_LENGTH], bHmac[CERT_HASH_LENGTH];
	BYTE pbSignature[0x200];
	ULONG cbSignature = sizeof(pbSignature);
	BCRYPT_PKCS1_PADDING_INFO pi = { BCRYPT_SHA1_ALGORITHM };

	// hash = SHA1(sign(SHA1(_M_bR1))_M_bR2)
	// RC4(hash)
	// HMAC(hash)

	DbgPrint("DecryptCredentials(%x)\r\n", cbCacheData);

	if (NOERROR == (hr = DoHash(BCRYPT_SHA1_ALGORITHM, _M_bR1, sizeof(_M_bR1), sha1, sizeof(sha1))))
	{
		if (S_OK == (hr = NCryptSetProperty(hKey, NCRYPT_PIN_PROPERTY, (PBYTE)pszPin, (ULONG)wcslen(pszPin)*sizeof(WCHAR), 0)))
		{
			if (S_OK == (hr = NCryptSignHash(hKey, &pi, sha1, sizeof(sha1), pbSignature, cbSignature, &cbSignature, BCRYPT_PAD_PKCS1)))
			{
				BCRYPT_KEY_HANDLE hBKey;

				if (S_OK == (hr = GetPublicKey(pCertInfo, &hBKey)))
				{
					hr = BCryptVerifySignature(hBKey, &pi, sha1, sizeof(sha1), pbSignature, cbSignature, BCRYPT_PAD_PKCS1);

					BCryptDestroyKey(hBKey);

					DbgPrint("VerifySignature=%x\r\n", hr);

					if (0 <= hr)
					{
						DATA_BLOB db[] = { { cbSignature, pbSignature }, { sizeof(_M_bR2), _M_bR2 } };

						reverse(pbSignature, cbSignature);

						if (S_OK == (hr = DoHash(BCRYPT_SHA1_ALGORITHM, db, _countof(db), sha1, sizeof(sha1))) &&
							S_OK == (hr = CreateSymKey(&hBKey, BCRYPT_RC4_ALGORITHM, sha1, 16)))
						{
							hr = BCryptDecrypt(hBKey, _M_bEncrypted, cbCacheData, 0, 0, 0, _M_bEncrypted, cbCacheData, &cbCacheData, 0);

							BCryptDestroyKey(hBKey);

							DbgPrint("Decrypt=%x [%x]\r\n", hr, cbCacheData);

							if (S_OK == hr)
							{
								if (sizeof(HMAC) < cbCacheData && CERT_HASH_LENGTH == _M_Hmac._M_dwHmacSize)
								{
									if (S_OK == (hr = Hmac(BCRYPT_SHA1_ALGORITHM, sha1, 16 /** yes, 16, not 20 **/, 
										_M_bCacheData, cbCacheData -= sizeof(HMAC), bHmac, sizeof(bHmac))))
									{
										DumpBytes("Hmac#1: ", _M_Hmac._M_bHmac, CERT_HASH_LENGTH, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF);
										DumpBytes("Hmac#2: ", bHmac, CERT_HASH_LENGTH, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF);

										if (memcmp(bHmac, _M_Hmac._M_bHmac, CERT_HASH_LENGTH))
										{
											hr = STATUS_INVALID_SIGNATURE;
										}
										else
										{
											*ppv = _M_bCacheData, *pcb = cbCacheData;
										}
									}
								}
								else
								{
									hr = STATUS_INVALID_SIGNATURE;
								}
							}
						}
					}
				}
			}
		}
	}

	return hr;
}

HRESULT DecryptCredentials(_In_ PCERT_INFO pCertInfo, 
						   _In_ NCRYPT_KEY_HANDLE hKey, 
						   _In_ PCWSTR pszPin, 
						   _In_ PVOID pvCacheData, 
						   _In_ ULONG cbCacheData,
						   _Out_ PVOID *ppv,
						   _Out_ PULONG pcb)
{
	if (cbCacheData > sizeof(KERB_SUPP_CREDS))
	{
		return reinterpret_cast<KERB_SUPP_CREDS*>(pvCacheData)->DecryptCredentials(
			pCertInfo, hKey, pszPin, cbCacheData - sizeof(ScHelper_RandomCredBits), ppv, pcb);
	}

	return STATUS_BAD_DATA;
}

ULONG CertNameToStrEx(PCCERT_CONTEXT pCertContext, _Out_ PWSTR psz, _In_ DWORD csz)
{
	ULONG cb = CertNameToStrW(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject, CERT_X500_NAME_STR, psz, csz);
	if (cb > 1)
	{
		return cb;
	}

	UCHAR hash[32];
	if (CertGetCertificateContextProperty(pCertContext, CERT_KEY_IDENTIFIER_PROP_ID, hash, &(cb = sizeof(hash))))
	{
		if (CryptBinaryToStringW(hash, cb, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF, psz, &csz))
		{
			return csz + (psz != 0);
		}
	}

	return 0;
}

BOOL KerbGetCertificateHash(_In_ PCCERT_CONTEXT pCertContext, _Out_ PBYTE pCertHash, _Inout_ PULONG pcbCertHash)
{
	ULONG M, m;
	RtlGetNtVersionNumbers(&M, &m, 0);

	union {
		USHORT Version;
		struct  
		{
			UCHAR Minor;
			UCHAR Major;
		};
	};

	Major = (UCHAR)M, Minor = (UCHAR)m;

	return Version < _WIN32_WINNT_WIN8 
		? CertGetCertificateContextProperty(pCertContext, CERT_SHA1_HASH_PROP_ID, pCertHash, pcbCertHash)
		: CryptHashPublicKeyInfo(0, CALG_SHA1, 0, X509_ASN_ENCODING, 
		&pCertContext->pCertInfo->SubjectPublicKeyInfo, pCertHash, pcbCertHash);
}

HRESULT CLIENT_DATA::CacheLookup(_In_ PCCERT_CONTEXT pCertContext, 
								 _In_ NCRYPT_KEY_HANDLE hKey, 
								 _In_ PCWSTR pszPin)
{
	MSV1_0_CACHE_LOOKUP_REQUEST<MSV1_0_OWF_PASSWORD_LENGTH> request {
		MsV1_0CacheLookup, {}, {}, MSV1_0_CACHE_LOOKUP_CREDTYPE_NTOWF, MSV1_0_OWF_PASSWORD_LENGTH
	};

	UCHAR hash[CERT_HASH_LENGTH];
	ULONG cb = sizeof(hash);

	PCERT_INFO pCertInfo = pCertContext->pCertInfo;

	if (KerbGetCertificateHash(pCertContext, hash, &cb) &&
		CryptHashCertificate2(BCRYPT_MD4_ALGORITHM, 0, 0, hash, cb, request.CredentialSubmitBuffer, &request.CredentialInfoLength))
	{
		PWSTR pszSubject = 0, pszIssuer = 0;
		ULONG cchSubject = 0, cchIssuer = 0;

		while (
			(cchSubject = CertNameToStrEx(pCertContext, pszSubject, cchSubject)) &&
			(cchIssuer = CertNameToStrW(X509_ASN_ENCODING, &pCertInfo->Issuer, CERT_X500_NAME_STR, pszIssuer, cchIssuer))
			)
		{
			if (pszSubject)
			{
				pszSubject[cchSubject - 1] = '@';
				RtlInitUnicodeString(&request.UserName, pszSubject);

				DbgPrint("CacheLogon(%S)\r\n", pszPin);
				DbgPrint("@UserName: \"%wZ\"\r\n", &request.UserName);
				DumpBytes("@Password: ", hash, cb, CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF);
				DumpBytes("@NtOwfPassword: ", request.CredentialSubmitBuffer, request.CredentialInfoLength, 
					CRYPT_STRING_HEXRAW|CRYPT_STRING_NOCRLF);

				UNICODE_STRING AuthenticationPackage = RTL_CONSTANT_STRING(MSV1_0_PACKAGE_NAMEW);

				NTSTATUS ProtocolStatus, status;
				PMSV1_0_CACHE_LOOKUP_RESPONSE response = 0;
				if (0 <= (status = LSA(CallPackage(
					const_cast<PUNICODE_STRING>(&AuthenticationPackage), 
					&request, sizeof(request), (void**)&response, &(cb = 0), &ProtocolStatus))))
				{
					DbgPrint("ProtocolStatus=%x\r\n", ProtocolStatus);

					if (0 <= (status = ProtocolStatus) && response)
					{
						PVOID pv;

						if (0 <= (status = DecryptCredentials(pCertInfo, hKey, pszPin, 
							response->SupplementalCacheData, response->SupplementalCacheDataLength, &pv, &cb)))
						{
							Dump((NETLOGON_VALIDATION_SAM_INFO4*)response->ValidationInformation);
							status = CopyToClient(pv, cb);
						}

						LocalFree( response->SupplementalCacheData );
						LocalFree( response->ValidationInformation );
						LSA(FreeReturnBuffer(response));
					}
				}

				return status;
			}

			pszSubject = (PWSTR)alloca((cchSubject + cchIssuer) * sizeof(WCHAR));
			pszIssuer = pszSubject + cchSubject;
		}
	}

	return GetLastErrorEx();
}