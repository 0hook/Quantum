#include "Nexus.h"

#include <stdio.h>
#include <stdint.h>

typedef NTSTATUS(NTAPI *FnNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI *FnLdrGetProcedureAddress)(void *, void *, ULONG, void **);
typedef void(WINAPI *FnRtlExitUserThread)(NTSTATUS);

const char *Funcs[] = {
    "NtQueryInformationProcess",
    "LdrGetProcedureAddress",
    "RtlExitUserThread"};

void DemonstrateAPIProtection(void)
{
    printf("[*] Loading ntdll...\n");

    void *ntdll = SKGetModuleBase(L"ntdll.dll");
    if (!ntdll)
    {
        printf("[!] Failed to resolve ntdll.dll\n");
        return;
    }

    printf("[+] ntdll @ %p\n\n", ntdll);
    printf("[*] API Virtualization Demo:\n");
    printf("-----------------------------\n");

    for (int i = 0; i < sizeof(Funcs) / sizeof(Funcs[0]); i++)
    {
        const char *name = Funcs[i];

        void *addr = SKGetProcedureAddrForCaller(
            ntdll,
            name,
            SK_FLAG_ENABLE_SEH | SK_FLAG_DEEP_SCAN);

        if (addr)
            printf("[+] %s: %p\n", name, addr);
        else
            printf("    [!] Failed to resolve %s\n", name);
    }
}

void DemonstrateIntegrityChecks(void)
{
    printf("\n[*] Integrity Verification Demo:\n");
    printf("-------------------------------\n");

    DWORD integrityLevel = SKGetSystemIntegrityLevel();
    printf("[+] Process Integrity Level: ");
    if (integrityLevel & SK_INTEGRITY_SYSTEM)
        printf("SYSTEM\n");
    else if (integrityLevel & SK_INTEGRITY_HIGH)
        printf("HIGH\n");
    else if (integrityLevel & SK_INTEGRITY_NORMAL)
        printf("MEDIUM\n");
    else
        printf("LOW or UNTRUSTED\n");

    printf("[+] Self-integrity check: %s\n",
           SKSelfIntegrityCheck() ? "PASSED" : "FAILED");

    printf("[+] Virtual Machine Detection: %s\n",
           SKDetectVirtualMachine() ? "DETECTED" : "NOT DETECTED");

    printf("[+] Hardware ID: 0x%08X\n",
           SKGenerateHardwareID(SK_HWID_ALL));
}

void DemonstrateMemoryProtection(void)
{
    printf("\n[*] Memory Protection Demo:\n");
    printf("-------------------------\n");

    void *memBlock = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!memBlock)
    {
        printf("[!] Failed to allocate memory\n");
        return;
    }

    printf("[+] Allocated memory block @ %p\n", memBlock);

    for (int i = 0; i < 4096; i++)
    {
        ((BYTE *)memBlock)[i] = (BYTE)i;
    }

    printf("[+] Memory initialized with test pattern\n");

    BYTE signature[20] = {0};
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) &&
        CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash) &&
        CryptHashData(hHash, memBlock, 4096, 0))
    {
        DWORD hashLen = sizeof(signature);
        CryptGetHashParam(hHash, HP_HASHVAL, signature, &hashLen, 0);
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
    }

    printf("[+] Created memory signature\n");

    if (SKProtectMemoryRegion(memBlock, 4096, PAGE_READONLY))
    {
        printf("[+] Memory protection applied: PAGE_READONLY\n");
    }
    else
    {
        printf("[!] Failed to apply memory protection\n");
    }

    if (SKVerifyMemorySignature(memBlock, 4096, signature))
    {
        printf("[+] Memory signature verified successfully\n");
    }
    else
    {
        printf("[!] Memory signature verification failed\n");
    }

    VirtualFree(memBlock, 0, MEM_RELEASE);
    printf("[+] Memory released\n");
}

int main()
{
    printf("=== Quantum Virtualizer Demo ===\n\n");

    DemonstrateAPIProtection();
    DemonstrateIntegrityChecks();
    DemonstrateMemoryProtection();

    printf("\n=== Demo Complete ===\n");
    return 0;
}