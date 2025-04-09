#include "SK.h"

#include <stdio.h>
#include <stdint.h>

typedef NTSTATUS(NTAPI *FnNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI *FnLdrGetProcedureAddress)(void *, void *, ULONG, void **);
typedef void(WINAPI *FnRtlExitUserThread)(NTSTATUS);

const char *Funcs[] = {
    "NtQueryInformationProcess",
    "LdrGetProcedureAddress",
    "RtlExitUserThread"};

void *SKGetProcedureAddrForCaller(const void *base, const char *funcName, DWORD flags);

int main()
{
    printf("[*] loading ntdll...\n");

    void *ntdll = SKGetModuleBase(L"ntdll.dll");
    if (!ntdll)
    {
        printf("[!] failed to resolve ntdll.dll\n");
        return 1;
    }

    printf("[+] ntdll @ %p\n\n", ntdll);

    for (int i = 0; i < sizeof(Funcs) / sizeof(Funcs[0]); i++)
    {
        const char *name = Funcs[i];

        void *addr = SKGetProcedureAddrForCaller(
            ntdll,
            name,
            SK_FLAG_ENABLE_SEH // SEH enabled, trampoline by default
        );

        if (addr)
            printf("[+] %s: %p\n", name, addr);
        else
            printf("    [!] failed to resolve %s\n", name);
    }

    FnRtlExitUserThread fn = (FnRtlExitUserThread)(uintptr_t)SKGetProcedureAddrForCaller(
        ntdll,
        "RtlExitUserThread",
        SK_FLAG_ENABLE_SEH);

    if (fn)
    {
        printf("\n[~] calling RtlExitUserThread(0xDEAD)\n");
        fn(0xDEAD);
    }
    else
    {
        printf("[!] failed to resolve RtlExitUserThread\n");
    }

    return 0;
}