#pragma once

#ifndef __wtypes_h__
#include <wtypes.h>
#endif

#ifndef __WINDEF_
#include <windef.h>
#endif

#include <string>

BOOL Dump(LPWSTR dumpPath);
BOOL ResolveFunctions();
BOOL Requirements();
DWORD GetPid();
HANDLE GetHandle(DWORD dwPid);
std::string GetDebugDLLPath();
HANDLE CreateDumpFile(LPWSTR path);
BOOL DeleteDumpFile(LPWSTR path);
DWORD GetWinVersion();