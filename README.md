<img src="pics/title.png" style="align: center;">

---

**[PEBLoader.h](https://github.com/DosX-dev/PEBLoader.h/blob/main/include/PEBLoader.h)** allows easy hiding of WinAPI imports via PEB walking technique. No more obvious API calls in your import table!

## What is this?

PEBLoader.h is a single-header library that lets you dynamically resolve Windows API functions without having them appear in your executable's import table. Instead of directly linking to functions like `LoadLibraryA` or `GetProcAddress`, this library walks the Process Environment Block (PEB) to find loaded modules and their exported functions.

Why would you want this? Well, some security tools and reverse engineers look at import tables to understand what your program does. With PEBLoader.h, your import table stays clean while you still get full access to the Windows API.

## How it works

The magic happens through PEB walking:

1. **Find modules by hash** - Instead of storing module names as strings, we use Adler-32 hashes
2. **Parse export tables manually** - We dig into PE headers to find function addresses
3. **No direct imports** - Your executable won't show obvious API dependencies

Here's what a typical workflow looks like:

```c
#include "PEBLoader.h"

int main() {
    // Load a library without it showing up in static analysis
    HMODULE hUser32 = LoadLibraryA_PEB("user32.dll");

    // Get a function address using our custom GetProcAddress
    typedef int (WINAPI *pMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
    pMessageBoxA MyMessageBox = (pMessageBoxA)GetProcAddress_PEB(hUser32, "MessageBoxA");

    // Use it normally
    MyMessageBox(NULL, "Hello from hidden API!", "Demo", MB_OK);

    // Clean up
    FreeLibrary_PEB(hUser32);
    return 0;
}
```

## Advanced usage

Want to be extra sneaky? You can resolve functions by hash too:

```c
// First, calculate the hash of your target function
// You can use an online Adler-32 calculator or the included function

// Just for example:
uint32_t hash_MessageBoxA = CLoaderAdler32("MessageBoxA", 11); // = 0x...

HMODULE hUser32 = LoadLibrary_PEB("user32.dll");
// Then resolve it directly by hash (no strings!)
void* pMsgBox = CLoaderDynGetProcAddressByAdler32(hUser32, hash_MessageBoxA);
```

This way, your executable contains zero readable strings related to the APIs you're using.

## API Reference

### Core Functions

**`CLoaderDynGetModuleByAdler32(uint32_t hash)`**

-   Finds a **loaded** module by its name hash (`kernel32.dll` and `ntdll.dll` are always loaded by default)
-   Returns module handle or NULL if not found

**`CLoaderDynGetProcAddressByAdler32(HMODULE hModule, uint32_t hash)`**

-   Finds an exported function by its name hash
-   Returns function address or NULL if not found

**`CLoaderAdler32(const char *data, size_t len)`**

-   Computes Adler-32 hash of given data
-   Use this to generate hashes for your target functions

### Wrapper Functions

These work exactly like their Windows API counterparts, but use PEB walking internally:

-   **`LoadLibraryA_PEB(LPCSTR lpLibFileName)`**
-   **`FreeLibrary_PEB(HMODULE hLibModule)`**
-   **`GetProcAddress_PEB(HMODULE hModule, LPCSTR lpProcName)`**

## Compiler Support

This library was originally designed for **Tiny C Compiler (TCC)** and has been extensively tested with it. While it might work with other compilers like GCC or MSVC, **we haven't tested it on anything else**, so your mileage may vary.

If you're using TCC, you're golden. For other compilers, you might need to tweak the inline assembly or structure definitions.

## Building

Since it's a header-only library, just include it:

```c
#include "PEBLoader.h"
```

Compile with TCC:

```bash
tcc -o myprogram.exe myprogram.c
```

## Platform Support

-   ✅ Windows x86 (32-bit)
-   ✅ Windows x64 (64-bit)
-   ❌ Linux, macOS (PEB is Windows-specific)

## Security Notes

This library is intended for:

-   Security research
-   Legitimate red team exercises
-   Educational purposes
-   Avoiding false positives from overzealous security tools

**Don't use this for malicious purposes.** We're not responsible for what you do with it.

Also keep in mind:

-   Advanced analysis tools can still detect PEB walking
-   Runtime behavior analysis will catch API calls regardless
-   This is obfuscation, not encryption

## Examples

Check out these real-world examples:

**Simple DLL loading:**

```c
HMODULE hAdvapi = LoadLibraryA_PEB("advapi32.dll");
typedef BOOL (WINAPI *pOpenProcessToken)(HANDLE, DWORD, PHANDLE);
pOpenProcessToken MyOpenProcessToken = (pOpenProcessToken)GetProcAddress_PEB(hAdvapi, "OpenProcessToken");
```

**Hash-based resolution (maximum stealth):**

```c
#define HASH_ntdll_dll 0x120f0389  // Your precomputed hash
#define HASH_NtQuerySystemInformation 0x7a0909e4

HMODULE hNtdll = CLoaderDynGetModuleByAdler32(HASH_ntdll_dll);
void* pNtQuery = CLoaderDynGetProcAddressByAdler32(hNtdll, HASH_NtQuerySystemInformation);
```
