#pragma once

#ifndef __wtypes_h__
#include <wtypes.h>
#endif

#ifndef __WINDEF_
#include <windef.h>
#endif

#include <DbgHelp.h>

#define OBJ_CASE_INSENSITIVE 0x00000040L
#define FILE_CREATE 2
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020

typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef LONG KPRIORITY;

typedef struct _SYSTEM_PROCESSES {
    ULONG NextEntryDelta;
    ULONG ThreadCount;
    ULONG Reserved1[6];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ProcessName;
    KPRIORITY BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
} SYSTEM_PROCESSES, * PSYSTEM_PROCESSES;

// RTL function prototypes
typedef void (WINAPI* fnRtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

typedef NTSYSAPI BOOLEAN(NTAPI* fnRtlEqualUnicodeString)(
    PUNICODE_STRING String1,
    PCUNICODE_STRING String2,
    BOOLEAN CaseInSensitive
    );

// MiniDumpWriteDump prototype
typedef BOOL(WINAPI* fnMiniDumpWriteDump)(
    HANDLE                            hProcess,
    DWORD                             ProcessId,
    HANDLE                            hFile,
    MINIDUMP_TYPE                     DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
    );

fnMiniDumpWriteDump GetMiniDumpWriteDump();

BOOL ATPMiniDumpWriteDumpCallback(PVOID CallbackParam, const PMINIDUMP_CALLBACK_INPUT CallbackInput, PMINIDUMP_CALLBACK_OUTPUT CallbackOutput);

// PSS snapshot functions
typedef enum
{
    PSS_CAPTURE_NONE = 0x00000000,
    PSS_CAPTURE_VA_CLONE = 0x00000001,
    PSS_CAPTURE_RESERVED_00000002 = 0x00000002,
    PSS_CAPTURE_HANDLES = 0x00000004,
    PSS_CAPTURE_HANDLE_NAME_INFORMATION = 0x00000008,
    PSS_CAPTURE_HANDLE_BASIC_INFORMATION = 0x00000010,
    PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION = 0x00000020,
    PSS_CAPTURE_HANDLE_TRACE = 0x00000040,
    PSS_CAPTURE_THREADS = 0x00000080,
    PSS_CAPTURE_THREAD_CONTEXT = 0x00000100,
    PSS_CAPTURE_THREAD_CONTEXT_EXTENDED = 0x00000200,
    PSS_CAPTURE_RESERVED_00000400 = 0x00000400,
    PSS_CAPTURE_VA_SPACE = 0x00000800,
    PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION = 0x00001000,
    PSS_CAPTURE_IPT_TRACE = 0x00002000,

    PSS_CREATE_BREAKAWAY_OPTIONAL = 0x04000000,
    PSS_CREATE_BREAKAWAY = 0x08000000,
    PSS_CREATE_FORCE_BREAKAWAY = 0x10000000,
    PSS_CREATE_USE_VM_ALLOCATIONS = 0x20000000,
    PSS_CREATE_MEASURE_PERFORMANCE = 0x40000000,
    PSS_CREATE_RELEASE_SECTION = 0x80000000
} PSS_CAPTURE_FLAGS;

DWORD snapshotFlags = PSS_CAPTURE_VA_CLONE
                        | PSS_CAPTURE_HANDLES
                        | PSS_CAPTURE_HANDLE_NAME_INFORMATION
                        | PSS_CAPTURE_HANDLE_BASIC_INFORMATION
                        | PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION
                        | PSS_CAPTURE_HANDLE_TRACE
                        | PSS_CAPTURE_THREADS
                        | PSS_CAPTURE_THREAD_CONTEXT
                        | PSS_CAPTURE_THREAD_CONTEXT_EXTENDED
                        | PSS_CREATE_BREAKAWAY
                        | PSS_CREATE_BREAKAWAY_OPTIONAL
                        | PSS_CREATE_USE_VM_ALLOCATIONS
                        | PSS_CREATE_RELEASE_SECTION;

DECLARE_HANDLE(HPSS);

typedef DWORD(WINAPI* fnPssCaptureSnapshot)(
    HANDLE            ProcessHandle,
    PSS_CAPTURE_FLAGS CaptureFlags,
    DWORD             ThreadContextFlags,
    HPSS*             SnapshotHandle
    );

typedef DWORD(WINAPI* fnPssFreeSnapshot)(
    HANDLE ProcessHandle,
    HPSS   SnapshotHandle
    );
