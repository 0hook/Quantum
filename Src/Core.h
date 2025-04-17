#pragma once

#ifndef SK_DEFS_H
#define SK_DEFS_H

#include <windows.h>

#if defined(__clang__)
#define SK_COMPILER_CLANG 1
#elif defined(_MSC_VER)
#define SK_COMPILER_MSVC 1
#else
#error "Unsupported compiler"
#endif

#if defined(SK_COMPILER_CLANG)
#define SK_FORCEINLINE __attribute__((always_inline)) inline
#define SK_FASTCALL __attribute__((fastcall))
#elif defined(SK_COMPILER_MSVC)
#define SK_FORCEINLINE __forceinline
#define SK_FASTCALL __fastcall
#endif

#define SK_INTEGRITY_NORMAL 0x1
#define SK_INTEGRITY_HIGH 0x2
#define SK_INTEGRITY_SYSTEM 0x4
#define SK_INTEGRITY_ALL 0x7

#define SK_HWID_VOLUME 0x1
#define SK_HWID_CPU 0x2
#define SK_HWID_BIOS 0x4
#define SK_HWID_ALL 0x7

#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING;
#endif

#ifndef _LDR_DATA_TABLE_ENTRY_DEFINED
#define _LDR_DATA_TABLE_ENTRY_DEFINED
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    void *DllBase;
    void *EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY;
#endif

#ifndef _PEB_LDR_DATA_DEFINED
#define _PEB_LDR_DATA_DEFINED
typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    void *SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA;
#endif

#ifndef _PEB_DEFINED
#define _PEB_DEFINED
typedef struct _PEB
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    void *Reserved3[2];
    PEB_LDR_DATA *Ldr;
} PEB;
#endif

#endif