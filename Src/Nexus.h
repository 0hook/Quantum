#pragma once

#include <windows.h>
#include <winnt.h>
#include <intrin.h>
#include <stddef.h>
#include <string.h>

#include "Core.h"

#ifdef __cplusplus
extern "C"
{
#endif

#define MAX_FRAMES 64
#define TRAMPOLINE_SIZE 32
#define SK_EXCEPTION_HOOK_DETECTED 0xE00000FF
#define SK_EXCEPTION_TAMPER_DETECTED 0xE00000EE

#define SK_FLAG_NONE 0x0
#define SK_FLAG_ENABLE_SEH 0x1
#define SK_FLAG_DISABLE_TRAMPOLINE 0x2
#define SK_FLAG_DEEP_SCAN 0x4
#define SK_FLAG_MEMORY_PROTECT 0x8
#define SK_FLAG_VERIFY_SIGNATURE 0x10

#define SK_PROXY_PAGE_COUNT 4
#define SK_PROXY_PAGE_SIZE 4096
#define SK_PROXY_SLOT_SIZE 32
#define SK_PROXYS_PER_PAGE (SK_PROXY_PAGE_SIZE / SK_PROXY_SLOT_SIZE)
#define SK_TOTAL_SLOTS (SK_PROXY_PAGE_COUNT * SK_PROXYS_PER_PAGE)

    typedef struct
    {
        DWORD Hash;
        void *OriginalFunc;
        void *TrampolineAddr;
        ULONGLONG LastUsedTick;
    } SK_PROXY_SLOT;

    typedef struct
    {
        void *Address;
        const char *Symbol;
    } StackFrameHit;

    typedef struct
    {
        void *HookedFunc;
        void *CleanProxy;
        const void *ModuleBase;
    } SK_HOOK_CONTEXT;

    extern void *gProxyPages[SK_PROXY_PAGE_COUNT];
    extern SK_PROXY_SLOT gProxyTable[SK_TOTAL_SLOTS];
    extern volatile LONG gProxySlotCounter;

    void *SKGetModuleBase(const wchar_t *moduleName);
    void *SKGetProcedureAddrForCaller(const void *base, const char *funcName, DWORD flags);

    BOOL SKVerifyProcessIntegrity(void);
    DWORD SKGetSystemIntegrityLevel(void);

    void SKProxyLRU(ULONGLONG olderThan);
    void SKStackScan(StackFrameHit *hits, int *count);

    BOOL SKProtectMemoryRegion(void *address, SIZE_T size, DWORD protection);
    BOOL SKVerifyMemorySignature(void *address, SIZE_T size, const BYTE *signature);
    DWORD SKGenerateHardwareID(DWORD components);
    BOOL SKDetectVirtualMachine(void);
    BOOL SKSelfIntegrityCheck(void);

#ifdef __cplusplus
}
#endif