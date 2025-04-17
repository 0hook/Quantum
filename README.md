# Quantum Virtualizer

A high-performance, professional-grade API call virtualization framework designed to protect applications from hooking and IAT manipulation.

## Changelog

```
v1.0.2 (2025-04-17)
-------------------
[+] Added hardware ID generation
[+] Added memory protection and signature verification
[+] Added virtual machine detection
[+] Added self-integrity check
[+] Added process integrity level detection
[+] Improved API call virtualization with deep scanning

v1.0.1 (2025-04-09)
-------------------
[+] Added support for Clang compiler
[+] Improved kernel-mode protection
[*] Fixed memory leaks in Nexus.c
```

## Features

- **Advanced Anti-Hooking**
  - Dynamic API call obfuscation
  - IAT protection and virtualization
  - Trampoline generation and management
  - Deep scanning for hook detection

- **Memory Security**
  - Memory region protection
  - Memory signature verification
  - Self-integrity verification
  - Code execution path validation

- **System Security**
  - Process integrity level detection
  - Hardware ID generation
  - Virtual machine detection
  - Execution environment analysis

- **Performance Optimization**
  - Minimal overhead architecture
  - LRU-based proxy cache
  - Efficient memory management
  - Optimized hash-based lookups

## Applications

- Software protection and anti-tampering
- Anti-cheat systems
- DRM implementation
- Malware research and analysis
- Critical application security
- License validation and hardware-binding

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

## API Reference

### Core Functions

- `SKGetModuleBase` - Safely resolves module base address
- `SKGetProcedureAddrForCaller` - Retrieves virtualized API address
- `SKVerifyProcessIntegrity` - Validates process integrity
- `SKGetSystemIntegrityLevel` - Gets detailed integrity information

### Memory Protection

- `SKProtectMemoryRegion` - Applies protection to memory regions
- `SKVerifyMemorySignature` - Validates memory region integrity
- `SKSelfIntegrityCheck` - Verifies application code integrity

### System Security

- `SKGenerateHardwareID` - Creates unique hardware identifier
- `SKDetectVirtualMachine` - Detects virtualized environments

### Advanced Features

- `SKProxyLRU` - Manages virtualization trampoline cache
- `SKStackScan` - Analyzes execution call stack

## Usage Example

```c
#include "Nexus.h"
#include <stdio.h>

int main()
{
    // Load module and resolve protected API
    void *ntdll = SKGetModuleBase(L"ntdll.dll");
    void *funcAddr = SKGetProcedureAddrForCaller(
        ntdll,
        "NtQueryInformationProcess",
        SK_FLAG_ENABLE_SEH | SK_FLAG_DEEP_SCAN
    );
    
    // Verify execution environment
    DWORD integrityLevel = SKGetSystemIntegrityLevel();
    BOOL isVM = SKDetectVirtualMachine();
    DWORD hwid = SKGenerateHardwareID(SK_HWID_ALL);
    
    // Protect sensitive memory
    void *sensitiveData = AllocateMemory();
    SKProtectMemoryRegion(sensitiveData, dataSize, PAGE_READONLY);
    
    // Verify application integrity
    if (!SKSelfIntegrityCheck()) {
        // Handle integrity violation
    }
    
    return 0;
}
```

## Security Considerations

This tool is intended for legitimate software protection. Use responsibly and in compliance with applicable laws and regulations.

### Best Practices

- Combine multiple protection techniques for defense-in-depth
- Implement secure error handling for protection failures
- Regularly update security measures against new attack vectors
- Consider using hardware-bound licensing for critical applications

## License

This project is licensed under the [MIT License](LICENSE).
