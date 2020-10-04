#pragma once

#ifndef __wtypes_h__
#include <wtypes.h>
#endif

#ifndef __WINDEF_
#include <windef.h>
#endif

#include <vector>
#include <tuple>

// Struct:      HOOKED_FUNCTION
// Describes:   A hooked function.
// Source:      https://github.com/jthuraisamy/TelemetrySourcerer/
// Members:
// - ModuleHandle: Handle to the function's module.
// - Ordinal:      The ordinal number of the function.
// - Address:      The address of the function.
// - Name:         Name of the function, if it exists.
// - FreshBytes:   Fresh copy of the function stub from disk.
typedef struct _HOOKED_FUNCTION {
    HMODULE ModuleHandle   = 0;
    DWORD   Ordinal        = 0;
    LPVOID  Address        = nullptr;
    WCHAR   Name[MAX_PATH] = { 0 };
    UCHAR   FreshBytes[16] = { 0 };
} HOOKED_FUNCTION, *PHOOKED_FUNCTION;

// Struct:      LOADED_MODULE
// Describes:   A loaded module.
// Source:      https://github.com/jthuraisamy/TelemetrySourcerer/
// Members:
// - Handle:          Handle to the function's module.
// - Path:            File path of module.
// - HookedFunctions: Array of hooked functions.
typedef struct _LOADED_MODULE {
    HMODULE Handle = 0;
    WCHAR Path[MAX_PATH] = { 0 };
    std::vector<PHOOKED_FUNCTION> HookedFunctions;
} LOADED_MODULE, *PLOADED_MODULE;

VOID PatchHooks();
std::tuple<HMODULE*, DWORD> GetModules();
BOOL CheckModuleForHooks(PLOADED_MODULE pModule);
BOOL RestoreHookedFunction(PHOOKED_FUNCTION pHookedFunction);
