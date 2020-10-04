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

typedef NTSTATUS(WINAPI* fnRtlGetVersion)(PRTL_OSVERSIONINFOEXW);

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
