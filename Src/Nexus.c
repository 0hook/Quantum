#include "Nexus.h"

void *gProxyPages[SK_PROXY_PAGE_COUNT] = {0};
SK_PROXY_SLOT gProxyTable[SK_TOTAL_SLOTS] = {0};
volatile LONG gProxySlotCounter = 0;

SK_FORCEINLINE DWORD SK_FASTCALL SKHash(const char *str)
{
    DWORD hash = 0x811C9DC5;
    DWORD key = 0xA3B376C9;
    char c;

    while ((c = *str++))
    {
        c |= 0x20;
        c ^= (char)key;
        hash ^= c;
        hash *= 0x01000193;
        key = _rotl(key ^ c, 5);
    }

    hash ^= hash >> 13;
    hash *= 0x5bd1e995;
    hash ^= hash >> 15;

    return hash;
}

SK_FORCEINLINE BOOL SKIsLikelyHook(const BYTE *p)
{
    if (p[0] == 0xE9)
        return TRUE; // JMP rel32
    if (p[0] == 0xFF && (p[1] & 0xF8) == 0x25)
        return TRUE; // JMP [rip+imm]
    if (p[0] == 0x68 && p[5] == 0xC3)
        return TRUE; // PUSH addr + RET
    return FALSE;
}

SK_FORCEINLINE int SKFindFreeSlotFast()
{
    int start = InterlockedCompareExchange(&gProxySlotCounter, 0, 0);

    for (int i = 0; i < SK_TOTAL_SLOTS; ++i)
    {
        int idx = (start + i) % SK_TOTAL_SLOTS;
        if (!gProxyTable[idx].TrampolineAddr)
            return idx;
    }

    return InterlockedIncrement(&gProxySlotCounter) % SK_TOTAL_SLOTS;
}

SK_FORCEINLINE void SKSafeCopyProxy(void *dst, const void *src, size_t size)
{
    const BYTE *srcBytes = (const BYTE *)src;
    BYTE *dstBytes = (BYTE *)dst;

    if (SKIsLikelyHook(srcBytes))
    {
        dstBytes[0] = 0xC3;
        memset(dstBytes + 1, 0xCC, size - 1);
    }
    else
    {
        memcpy(dstBytes, srcBytes, size);
    }
}

SK_FORCEINLINE void *SKProxyResolveHashed(DWORD hash, const void *func)
{
    ULONGLONG now = __rdtsc();

    for (int i = 0; i < SK_TOTAL_SLOTS; ++i)
    {
        if (gProxyTable[i].Hash == hash)
        {
            gProxyTable[i].LastUsedTick = now;
            return gProxyTable[i].TrampolineAddr;
        }
    }

    int index = SKFindFreeSlotFast();
    int pageIndex = index / SK_PROXYS_PER_PAGE;
    int offset = index % SK_PROXYS_PER_PAGE;

    if (!gProxyPages[pageIndex])
    {
        void *newPage = VirtualAlloc(NULL, SK_PROXY_PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!newPage)
            return NULL;

        if (InterlockedCompareExchangePointer(&gProxyPages[pageIndex], newPage, NULL) != NULL)
        {
            VirtualFree(newPage, 0, MEM_RELEASE);
        }
    }

    void *page = gProxyPages[pageIndex];
    void *slotAddr = (BYTE *)page + offset * SK_PROXY_SLOT_SIZE;

    if (gProxyTable[index].TrampolineAddr)
    {
        SecureZeroMemory(gProxyTable[index].TrampolineAddr, SK_PROXY_SLOT_SIZE);
    }

    SKSafeCopyProxy(slotAddr, func, SK_PROXY_SLOT_SIZE);

    gProxyTable[index].Hash = hash;
    gProxyTable[index].OriginalFunc = (void *)func;
    gProxyTable[index].TrampolineAddr = slotAddr;
    gProxyTable[index].LastUsedTick = now;

    return slotAddr;
}

SK_FORCEINLINE BOOL SKIsFuncOutOfTextSect(const void *func, const void *base)
{
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)((const BYTE *)base + ((const IMAGE_DOS_HEADER *)base)->e_lfanew);
    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
    {
        if (memcmp(sec->Name, ".text", 5) == 0)
        {
            const BYTE *start = (const BYTE *)base + sec->VirtualAddress;
            const BYTE *end = start + sec->Misc.VirtualSize;
            return (const BYTE *)func < start || (const BYTE *)func > end;
        }
    }

    return FALSE;
}

SK_FORCEINLINE void *SKStepoverIfHooked(DWORD hash, const void *func, const void *base, DWORD flags)
{
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)((const BYTE *)base + ((const IMAGE_DOS_HEADER *)base)->e_lfanew);
    const IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec)
    {
        if (memcmp(sec->Name, ".text", 5) == 0)
        {
            const BYTE *start = (const BYTE *)base + sec->VirtualAddress;
            const BYTE *end = start + sec->Misc.VirtualSize;

            if ((const BYTE *)func < start || (const BYTE *)func > end)
                return NULL;

            void *trampoline = SKProxyResolveHashed(hash, func);
            if (!trampoline)
                return NULL;

#if defined(_DEBUG)
            if (flags & SK_FLAG_ENABLE_SEH)
            {
                __try
                {
                    RaiseException(SK_EXCEPTION_HOOK_DETECTED, 0, 0, NULL);
                }
                __except (GetExceptionCode() == SK_EXCEPTION_HOOK_DETECTED
                              ? EXCEPTION_EXECUTE_HANDLER
                              : EXCEPTION_CONTINUE_SEARCH)
                {
                }
            }
#endif

            return trampoline;
        }
    }

    return NULL;
}

void SKStackScan(StackFrameHit *hits, int *count)
{
    void **frame = (void **)_AddressOfReturnAddress();
    int i = 0;

    __try
    {
        while (i < MAX_FRAMES && frame)
        {
            void *rip = *(frame + 1);
            if (!rip)
                break;

            if (i == 0 || hits[i - 1].Address != rip)
            {
                hits[i].Address = rip;
                hits[i++].Symbol = NULL;
            }

            frame = (void **)(*frame);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        // rofl
    }

    *count = i;
}

void SKProxyLRU(ULONGLONG olderThan)
{
    ULONGLONG now = __rdtsc();
    for (int i = 0; i < SK_TOTAL_SLOTS; ++i)
    {
        if (gProxyTable[i].TrampolineAddr &&
            (now - gProxyTable[i].LastUsedTick) > olderThan)
        {

            SecureZeroMemory(gProxyTable[i].TrampolineAddr, SK_PROXY_SLOT_SIZE);

            gProxyTable[i].Hash = 0;
            gProxyTable[i].OriginalFunc = NULL;
            gProxyTable[i].TrampolineAddr = NULL;
            gProxyTable[i].LastUsedTick = 0;
        }
    }
}

void *SKGetModuleBase(const wchar_t *name)
{
    const PEB *peb = (PEB *)__readgsqword(0x60);
    const LIST_ENTRY *list = &peb->Ldr->InMemoryOrderModuleList;

    for (const LIST_ENTRY *curr = list->Flink; curr != list; curr = curr->Flink)
    {
        const LDR_DATA_TABLE_ENTRY *entry = (const LDR_DATA_TABLE_ENTRY *)((const BYTE *)curr - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
        if (!_wcsicmp(entry->BaseDllName.Buffer, name))
            return entry->DllBase;
    }

    return NULL;
}

void *SKGetProcedureAddrForCaller(const void *base, const char *funcName, DWORD flags)
{
    DWORD targetHash = SKHash(funcName);

    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)((const BYTE *)base + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY *dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress)
        return NULL;

    const IMAGE_EXPORT_DIRECTORY *exp = (const IMAGE_EXPORT_DIRECTORY *)((const BYTE *)base + dir->VirtualAddress);
    const DWORD *names = (const DWORD *)((const BYTE *)base + exp->AddressOfNames);
    const DWORD *funcs = (const DWORD *)((const BYTE *)base + exp->AddressOfFunctions);
    const WORD *ords = (const WORD *)((const BYTE *)base + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i)
    {
        const char *name = (const char *)base + names[i];
        if (SKHash(name) != targetHash)
            continue;

        void *resolved = (BYTE *)base + funcs[ords[i]];

        if (SKIsFuncOutOfTextSect(resolved, base))
        {
            void *stub = SKStepoverIfHooked(targetHash, resolved, base, flags);
            if (stub)
                return stub;
        }

#if defined(_DEBUG)
        StackFrameHit hits[MAX_FRAMES];
        int count = 0;
        SKStackScan(hits, &count);
        for (int j = 0; j < count; ++j)
        {
            char msg[64];
            sprintf_s(msg, sizeof(msg), "[SK] return frame @ %p\n", hits[j].Address);
            OutputDebugStringA(msg);
        }
#endif

        return resolved;
    }

    return NULL;
}

BOOL SKVerifyProcessIntegrity(void)
{
    BOOL result = FALSE;
    HANDLE hProcess = GetCurrentProcess();
    DWORD cbNeeded = 0;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hProcess))
    {
        return FALSE;
    }

    BYTE tokenInfoBuffer[64] = {0};
    if (GetTokenInformation(hProcess, TokenIntegrityLevel, tokenInfoBuffer, sizeof(tokenInfoBuffer), &cbNeeded))
    {
        PTOKEN_MANDATORY_LABEL tokenInfo = (PTOKEN_MANDATORY_LABEL)tokenInfoBuffer;
        DWORD integrityLevel = *GetSidSubAuthority(tokenInfo->Label.Sid,
                                                   *GetSidSubAuthorityCount(tokenInfo->Label.Sid) - 1);

        if (integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID)
        {
            result = TRUE;
        }
    }

    CloseHandle(hProcess);
    return result;
}

DWORD SKGetSystemIntegrityLevel(void)
{
    DWORD result = 0;
    HANDLE hProcess = GetCurrentProcess();
    DWORD cbNeeded = 0;

    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hProcess))
    {
        return 0;
    }

    BYTE tokenInfoBuffer[64] = {0};
    if (GetTokenInformation(hProcess, TokenIntegrityLevel, tokenInfoBuffer, sizeof(tokenInfoBuffer), &cbNeeded))
    {
        PTOKEN_MANDATORY_LABEL tokenInfo = (PTOKEN_MANDATORY_LABEL)tokenInfoBuffer;
        DWORD integrityLevel = *GetSidSubAuthority(tokenInfo->Label.Sid,
                                                   *GetSidSubAuthorityCount(tokenInfo->Label.Sid) - 1);

        if (integrityLevel >= SECURITY_MANDATORY_SYSTEM_RID)
        {
            result |= SK_INTEGRITY_SYSTEM;
        }
        else if (integrityLevel >= SECURITY_MANDATORY_HIGH_RID)
        {
            result |= SK_INTEGRITY_HIGH;
        }
        else if (integrityLevel >= SECURITY_MANDATORY_MEDIUM_RID)
        {
            result |= SK_INTEGRITY_NORMAL;
        }
    }

    CloseHandle(hProcess);
    return result;
}

BOOL SKProtectMemoryRegion(void *address, SIZE_T size, DWORD protection)
{
    DWORD oldProtect;
    if (!VirtualProtect(address, size, protection, &oldProtect))
    {
        return FALSE;
    }

    if (protection == PAGE_NOACCESS || protection == PAGE_READONLY)
    {
        FlushInstructionCache(GetCurrentProcess(), address, size);
    }

    return TRUE;
}

BOOL SKVerifyMemorySignature(void *address, SIZE_T size, const BYTE *signature)
{
    BYTE hash[20];
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    BOOL result = FALSE;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        return FALSE;
    }

    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return FALSE;
    }

    if (CryptHashData(hHash, (BYTE *)address, (DWORD)size, 0))
    {
        DWORD hashLen = sizeof(hash);
        if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0))
        {
            result = (memcmp(hash, signature, hashLen) == 0);
        }
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

DWORD SKGenerateHardwareID(DWORD components)
{
    DWORD result = 0;
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        return 0;
    }

    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        return 0;
    }

    if (components & SK_HWID_VOLUME)
    {
        char volumeSerial[128] = {0};
        DWORD serialNum = 0;
        GetVolumeInformationA("C:\\", NULL, 0, &serialNum, NULL, NULL, NULL, 0);
        sprintf_s(volumeSerial, sizeof(volumeSerial), "VOL:%08X", serialNum);
        CryptHashData(hHash, (BYTE *)volumeSerial, (DWORD)strlen(volumeSerial), 0);
    }

    if (components & SK_HWID_CPU)
    {
        int cpuInfo[4] = {0};
        __cpuid(cpuInfo, 1);
        CryptHashData(hHash, (BYTE *)cpuInfo, sizeof(cpuInfo), 0);
    }

    if (components & SK_HWID_BIOS)
    {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        CryptHashData(hHash, (BYTE *)&sysInfo, sizeof(sysInfo), 0);
    }

    BYTE hashBytes[20];
    DWORD hashLen = sizeof(hashBytes);
    if (CryptGetHashParam(hHash, HP_HASHVAL, hashBytes, &hashLen, 0))
    {
        result = *(DWORD *)hashBytes ^ *(DWORD *)(hashBytes + 4) ^ *(DWORD *)(hashBytes + 8) ^ *(DWORD *)(hashBytes + 12) ^ *(DWORD *)(hashBytes + 16);
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return result;
}

BOOL SKDetectVirtualMachine(void)
{
    int cpuInfo[4] = {0};
    char vendorID[13] = {0};

    __cpuid(cpuInfo, 0);
    *(int *)(vendorID) = cpuInfo[1];
    *(int *)(vendorID + 4) = cpuInfo[3];
    *(int *)(vendorID + 8) = cpuInfo[2];
    vendorID[12] = '\0';

    if (strcmp(vendorID, "VMwareVMware") == 0 ||
        strcmp(vendorID, "Microsoft Hv") == 0 ||
        strcmp(vendorID, "VBoxVBoxVBox") == 0)
    {
        return TRUE;
    }

    BOOL isVM = FALSE;

    __try
    {
        __asm
        {
            push eax
            push ebx
            push ecx
            push edx

            mov eax, 1
            cpuid
            test ecx, 0x80000000
            jnz vmx_present

            jmp not_vm

        vmx_present:
            mov isVM, 1

        not_vm:
            pop edx
            pop ecx
            pop ebx
            pop eax
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        isVM = FALSE;
    }

    return isVM;
}

BOOL SKSelfIntegrityCheck(void)
{
    HMODULE hModule = GetModuleHandleA(NULL);
    if (!hModule)
    {
        return FALSE;
    }

    const IMAGE_DOS_HEADER *dosHeader = (const IMAGE_DOS_HEADER *)hModule;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return FALSE;
    }

    const IMAGE_NT_HEADERS *ntHeaders = (const IMAGE_NT_HEADERS *)((const BYTE *)hModule + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return FALSE;
    }

    const IMAGE_SECTION_HEADER *sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, sectionHeader++)
    {
        if (memcmp(sectionHeader->Name, ".text", 5) == 0)
        {
            DWORD checksum = 0;
            const BYTE *start = (const BYTE *)hModule + sectionHeader->VirtualAddress;
            const BYTE *end = start + sectionHeader->Misc.VirtualSize;

            for (const BYTE *p = start; p < end; p++)
            {
                checksum = _rotl(checksum, 3) ^ *p;
            }

            return (checksum == ntHeaders->OptionalHeader.CheckSum);
        }
    }

    return FALSE;
}