#pragma once

#ifdef BOF
	// Ole32
	DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID,DWORD);
	#define CoInitializeEx OLE32$CoInitializeEx
	DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeSecurity(PSECURITY_DESCRIPTOR,LONG,SOLE_AUTHENTICATION_SERVICE*,void*,DWORD,DWORD,void*,DWORD,void*);
	#define CoInitializeSecurity OLE32$CoInitializeSecurity
	DECLSPEC_IMPORT void WINAPI OLE32$CoUninitialize(void);
	#define CoUninitialize OLE32$CoUninitialize
	DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateInstance(REFCLSID rclsid, LPUNKNOWN pUnkOuter, DWORD dwClsContext, REFIID riid, LPVOID *ppv);
	#define CoCreateInstance OLE32$CoCreateInstance
	DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoSetProxyBlanket(IUnknown*,DWORD,DWORD,OLECHAR*,DWORD,DWORD,RPC_AUTH_IDENTITY_HANDLE,DWORD);
	#define CoSetProxyBlanket OLE32$CoSetProxyBlanket

	// OleAuth32
	WINBASEAPI BSTR WINAPI OLEAUT32$SysAllocString(const OLECHAR *);
	#define SysAllocString OLEAUT32$SysAllocString
	WINBASEAPI HRESULT WINAPI OLEAUT32$VariantClear(VARIANTARG *);
	#define VariantClear OLEAUT32$VariantClear
	WINBASEAPI void WINAPI OLEAUT32$SysFreeString(BSTR);
	#define SysFreeString OLEAUT32$SysFreeString
#endif