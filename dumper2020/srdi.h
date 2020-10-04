#pragma once

#ifndef __wtypes_h__
#include <wtypes.h>
#endif

#ifndef __WINDEF_
#include <windef.h>
#endif

#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)
#define RVA(type, base, rva) (type)((ULONG_PTR) base + rva)

#define SRDI_CLEARHEADER 0x1
#define SRDI_CLEARMEMORY 0x2
#define SRDI_OBFUSCATEIMPORTS 0x4

typedef UINT_PTR(WINAPI * RDI)();

HMODULE LoadDLL(const char * cDllPath);
BOOL ConvertToShellcode(LPCSTR inFile, DWORD userFunction, LPVOID userData, DWORD userSize, DWORD flags, LPSTR &outBytes, DWORD &outSize);
BOOL GetFileContents(LPCSTR filename, LPSTR * data, DWORD & size);
FARPROC GetProcAddressR(HMODULE hModule, LPCSTR lpProcName);