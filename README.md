# Quantum Virtualizer

A high-performance, professional-grade API call virtualization framework designed to protect applications from hooking and IAT manipulation.

## Features

- Advanced anti-hooking mechanisms
- IAT protection and virtualization
- Minimal performance overhead
- Kernel-mode and user-mode protection
- Dynamic API call obfuscation
- Compatible with modern Windows applications

## Applications

- Software protection and anti-tampering
- Anti-cheat systems
- DRM implementation
- Malware research and analysis
- Critical application security

## Getting Started

### Prerequisites

- Visual Studio 2022 or later
- Windows 10/11
- C/C++ development experience

### Building

1. Clone the repository
2. Open `Quantum.sln` in Visual Studio
3. Build the solution in Release mode for optimal performance

## Project Structure

- `Src/Core.h` - Core definitions and security primitives
- `Src/Nexus.h` - API virtualization interface
- `Src/Nexus.c` - Implementation of protection mechanisms
- `Src/Example.c` - Usage examples and implementation patterns

## Usage Example

```c
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

    return 0;
}
```

## License

This project is licensed under the [MIT License](LICENSE).

## Security Considerations

This tool is intended for legitimate software protection. Use responsibly and in compliance with applicable laws and regulations.
