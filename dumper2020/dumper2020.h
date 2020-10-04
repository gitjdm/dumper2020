#pragma once

#ifndef __wtypes_h__
#include <wtypes.h>
#endif

#ifndef __WINDEF_
#include <windef.h>
#endif

#include <string>

BOOL Dump(const wchar_t* wcDumpPath);
BOOL ResolveHelpers();
BOOL Requirements();
DWORD GetPid();
HANDLE GetHandle(DWORD dwPid);
std::string GetDebugDLLPath();
HANDLE CreateDumpFile(const wchar_t* wcDumpPath);
BOOL DeleteDumpFile(const wchar_t* wcDumpPath);
DWORD GetWinVersion();