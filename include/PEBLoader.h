
/*
 * PEBLoader.h - Tiny C header that allows easy hiding of WinAPI imports via PEB
 *
 * Copyright (c) 2025 DosX-dev
 *
 * Repository: https://github.com/DosX-dev/PEBLoader.h
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef CLOADER_H
#define CLOADER_H

#include <stdint.h>
#include <windows.h>

#if !_WIN64
/**
 * @brief Reads a DWORD value from the FS segment register at the specified offset (x86 only)
 * 
 * This inline assembly function provides direct access to the FS segment register,
 * which points to the Thread Information Block (TIB) in 32-bit Windows.
 * The TIB contains pointers to important process structures including the PEB.
 * 
 * @param offset Offset within the FS segment to read from (e.g., 0x30 for PEB pointer)
 * @return ULONG_PTR value read from FS:[offset]
 * 
 * @note This function is only available on x86 (32-bit) builds
 * @note On x64, __readgsqword should be used with GS segment instead
 */
static inline ULONG_PTR __readfsdword(ULONG offset) {
    ULONG_PTR value;
    __asm__(
        "mov %%fs:(%1), %0"  // Read from FS segment at given offset
        : "=r"(value)        // Output operand
        : "r"(offset));      // Input operand
    return value;
}
#endif

/**
 * @brief Unicode string structure used by Windows kernel and ntdll
 * 
 * This structure represents a counted Unicode string with explicit length fields,
 * commonly used throughout Windows internal APIs and data structures.
 */
typedef struct _UNICODE_STRING {
    USHORT Length;         ///< Current length of the string in bytes (not characters)
    USHORT MaximumLength;  ///< Maximum capacity of the buffer in bytes
    PWSTR Buffer;          ///< Pointer to the Unicode string buffer
} UNICODE_STRING, *PUNICODE_STRING;

/**
 * @brief Loader Data Table Entry - represents a loaded module in the process
 * 
 * This structure contains information about a loaded DLL or EXE in the process.
 * It's part of the loader data structures maintained by the Windows loader and
 * can be accessed through PEB walking for stealth module enumeration.
 */
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;            ///< Links in load order list
    LIST_ENTRY InMemoryOrderLinks;          ///< Links in memory order list
    LIST_ENTRY InInitializationOrderLinks;  ///< Links in initialization order list
    PVOID DllBase;                          ///< Base address where the module is loaded
    PVOID EntryPoint;                       ///< Entry point of the module (DllMain for DLLs)
    ULONG SizeOfImage;                      ///< Size of the module image in memory
    UNICODE_STRING FullDllName;             ///< Full path to the DLL file
    UNICODE_STRING BaseDllName;             ///< Base name of the DLL (filename only)
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

/**
 * @brief Process Environment Block Loader Data - contains loader information
 * 
 * This structure maintains lists of loaded modules in different orders.
 * It's accessible through the PEB and provides an alternative way to enumerate
 * loaded modules without using documented Windows APIs.
 */
typedef struct _PEB_LDR_DATA {
    ULONG Length;                                ///< Size of this structure
    BOOLEAN Initialized;                         ///< TRUE if loader data is initialized
    HANDLE SsHandle;                             ///< Session handle
    LIST_ENTRY InLoadOrderModuleList;            ///< Head of load order module list
    LIST_ENTRY InMemoryOrderModuleList;          ///< Head of memory order module list
    LIST_ENTRY InInitializationOrderModuleList;  ///< Head of initialization order module list
} PEB_LDR_DATA, *PPEB_LDR_DATA;

/**
 * @brief Process Environment Block - simplified structure for essential fields
 * 
 * The PEB contains process-wide information and is accessible from user mode.
 * This simplified definition includes only the fields necessary for module enumeration.
 * The actual PEB structure contains many more fields.
 */
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;     ///< TRUE if address space was inherited
    BOOLEAN ReadImageFileExecOptions;  ///< TRUE if image file execution options were read
    BOOLEAN BeingDebugged;             ///< TRUE if process is being debugged
    BOOLEAN SpareBool;                 ///< Reserved boolean field
    HANDLE Mutant;                     ///< Handle to process mutant
    PVOID ImageBaseAddress;            ///< Base address of the process image
    PPEB_LDR_DATA Ldr;                 ///< Pointer to loader data structure
} PEB, *PPEB;

// Precomputed Adler-32 hashes for API obfuscation
// These hashes allow function resolution without storing plaintext API names
#define HASH_kernel32_dll 0x1d290451    // adler32("kernel32.dll")
#define HASH_LoadLibraryA 0x1d810497    // adler32("LoadLibraryA")
#define HASH_FreeLibrary 0x18f20458     // adler32("FreeLibrary")
#define HASH_GetProcAddress 0x27c7057b  // adler32("GetProcAddress")

// Function pointer typedefs for dynamically resolved Windows APIs
typedef HMODULE(WINAPI *pLoadLibraryA)(LPCSTR lpLibFileName);
typedef BOOL(WINAPI *pFreeLibrary)(HMODULE hLibModule);
typedef FARPROC(WINAPI *pGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);

/**
 * @brief Computes the Adler-32 checksum for the given data buffer.
 *
 * The Adler-32 checksum is a fast checksum algorithm, used for error detection in data transmission.
 * This function takes a pointer to a data buffer and its length, and returns the computed checksum.
 *
 * @param data Pointer to the input data buffer.
 * @param len Length of the input data buffer in bytes.
 * @return The computed Adler-32 checksum as a 32-bit unsigned integer.
 */
uint32_t CLoaderAdler32(const char *data, size_t len) {
    uint32_t a = 1, b = 0;

    for (size_t i = 0; i < len; ++i) {
        a += (uint8_t)data[i];
        b += a;
    }

    return ((b % 65521) << 16) | (a % 65521);
}

/**
 * @brief Retrieves a module handle from the current process by matching the Adler-32 hash of its name.
 *
 * This function iterates through the loaded modules in the current process using the PEB (Process Environment Block),
 * computes the Adler-32 hash of each module's name (converted to lowercase), and returns the handle (HMODULE) of the
 * module whose name matches the specified hash.
 *
 * @param hash The Adler-32 hash value of the module name to search for. If zero, the function performs no search.
 * @return HMODULE Handle to the matched module, or NULL if no module matches the given hash.
 *
 * @note
 * - The function works for both x86 and x64 architectures.
 * - Module names are converted to lowercase before hashing.
 * - The function relies on the implementation of CLoaderAdler32 for hash calculation.
 * - The function accesses internal Windows structures and is intended for advanced use cases.
 */
HMODULE CLoaderDynGetModuleByAdler32(uint32_t hash) {
    // Anti-analysis: crash if hash is zero (invalid parameter)
    if (!hash) __asm__ __volatile(".byte 0x00");

    PPEB peb;
    // Access PEB through Thread Information Block (TIB)
    // Different offsets for x64 (GS:0x60) vs x86 (FS:0x30)
#ifdef _WIN64
    peb = (PPEB)__readgsqword(0x60);  // x64: GS segment, offset 0x60
#else
    peb = (PPEB)__readfsdword(0x30);  // x86: FS segment, offset 0x30
#endif

    PPEB_LDR_DATA ldr = peb->Ldr;
    // Start walking the InLoadOrder module list
    PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink;

    while (entry->DllBase != NULL) {
        if (entry->BaseDllName.Buffer != NULL) {
            char moduleName[260];  // MAX_PATH equivalent for module names
            int len = 0;

            // Convert Unicode module name to ASCII and count length
            for (int i = 0; i < entry->BaseDllName.Length / 2 && i < 259; i++) {
                moduleName[i] = (char)entry->BaseDllName.Buffer[i];
                len++;
            }
            moduleName[len] = 0;  // Null-terminate the string

            // Convert to lowercase for consistent hashing
            // (Windows module names are case-insensitive)
            for (int i = 0; i < len; i++) {
                if (moduleName[i] >= 'A' && moduleName[i] <= 'Z') {
                    moduleName[i] += 32;  // Convert to lowercase
                }
            }

            // Compare computed hash with target hash
            if (CLoaderAdler32(moduleName, len) == hash) {
                return (HMODULE)entry->DllBase;
            }
        }

        // Move to next entry in the linked list
        entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;

        // Detect end of circular linked list (back to head)
        if (entry == (PLDR_DATA_TABLE_ENTRY)ldr->InLoadOrderModuleList.Flink) {
            break;
        }
    }

    return NULL;  // Module not found
}

/**
 * @brief Retrieves the address of an exported function from a module by matching the Adler-32 hash of its name
 *
 * This function performs manual PE export table parsing to locate functions by hash,
 * avoiding the use of GetProcAddress API which could be monitored or hooked.
 * 
 * @param hModule Handle to the loaded module (DLL or EXE) whose export table will be searched
 * @param hash Adler-32 hash value of the function name to search for
 * @return Pointer to the function if found; otherwise, NULL
 *
 * @note This function parses the PE export table manually for stealth operation
 * @note Function names are case-sensitive during hashing
 * @note Requires a valid implementation of CLoaderAdler32 for hash calculation
 */
void *CLoaderDynGetProcAddressByAdler32(HMODULE hModule, uint32_t hash) {
    // Parse PE headers to locate export directory
    IMAGE_DOS_HEADER *dosHeader = (IMAGE_DOS_HEADER *)hModule;
    IMAGE_NT_HEADERS *ntHeaders = (IMAGE_NT_HEADERS *)((BYTE *)hModule + dosHeader->e_lfanew);

    // Get export directory from data directory array
    IMAGE_EXPORT_DIRECTORY *exportDir = (IMAGE_EXPORT_DIRECTORY *)((BYTE *)hModule +
                                                                   ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // Extract export table arrays (all RVAs need base address added)
    DWORD *nameRVAs = (DWORD *)((BYTE *)hModule + exportDir->AddressOfNames);          // Function name RVAs
    WORD *ordinals = (WORD *)((BYTE *)hModule + exportDir->AddressOfNameOrdinals);     // Ordinal indices
    DWORD *functionRVAs = (DWORD *)((BYTE *)hModule + exportDir->AddressOfFunctions);  // Function RVAs

    // Iterate through all exported function names
    for (DWORD i = 0; i < exportDir->NumberOfNames; i++) {
        char *functionName = (char *)((BYTE *)hModule + nameRVAs[i]);

        // Calculate string length manually (no strlen dependency)
        size_t fn_len = 0;
        while (functionName[fn_len]) ++fn_len;

        // Compare hash of current function name with target hash
        if (CLoaderAdler32(functionName, fn_len) == hash) {
            // Use ordinal to index into function address array
            return (void *)((BYTE *)hModule + functionRVAs[ordinals[i]]);
        }
    }

    return NULL;  // Function not found in export table
}

/**
 * @brief PEB-based LoadLibraryA wrapper for stealth library loading
 * 
 * This function provides LoadLibraryA functionality by dynamically resolving
 * the actual LoadLibraryA function from kernel32.dll using PEB walking and hash-based
 * function resolution. This approach avoids direct API imports that could be detected.
 * 
 * @param lpLibFileName Pointer to a null-terminated string specifying the library file name
 * @return Handle to the loaded module, or NULL if the function fails
 * 
 * @note Crashes with invalid instruction if lpLibFileName is NULL (anti-analysis measure)
 * @note Uses hash-based resolution to avoid plaintext API names
 */
HMODULE WINAPI LoadLibraryA_PEB(LPCSTR lpLibFileName) {
    // Dynamically resolve kernel32.dll by hash
    HMODULE hKernel32 = CLoaderDynGetModuleByAdler32(HASH_kernel32_dll);

    // Dynamically resolve LoadLibraryA function by hash
    pLoadLibraryA dyn_LoadLibraryA = (pLoadLibraryA)CLoaderDynGetProcAddressByAdler32(hKernel32, HASH_LoadLibraryA);

    // Call the actual LoadLibraryA function
    return dyn_LoadLibraryA(lpLibFileName);
}

/**
 * @brief PEB-based FreeLibrary wrapper for stealth library unloading
 * 
 * This function provides FreeLibrary functionality by dynamically resolving
 * the actual FreeLibrary function from kernel32.dll using PEB walking and hash-based
 * function resolution. This maintains stealth operation consistency.
 * 
 * @param hLibModule Handle to the loaded library module to be freed
 * @return TRUE if the function succeeds, FALSE otherwise
 * 
 * @note Uses hash-based resolution to avoid plaintext API names
 * @note No NULL check performed on hLibModule (follows Windows API behavior)
 */
BOOL WINAPI FreeLibrary_PEB(HMODULE hLibModule) {
    // Dynamically resolve kernel32.dll by hash
    HMODULE hKernel32 = CLoaderDynGetModuleByAdler32(HASH_kernel32_dll);

    // Dynamically resolve FreeLibrary function by hash
    pFreeLibrary dyn_FreeLibrary = (pFreeLibrary)CLoaderDynGetProcAddressByAdler32(hKernel32, HASH_FreeLibrary);

    // Call the actual FreeLibrary function
    return dyn_FreeLibrary(hLibModule);
}

/**
 * @brief PEB-based GetProcAddress wrapper for stealth function resolution
 * 
 * This function provides GetProcAddress functionality by dynamically resolving
 * the actual GetProcAddress function from kernel32.dll using PEB walking and hash-based
 * function resolution. This allows for complete API resolution without imports.
 * 
 * @param hModule Handle to the DLL module containing the function
 * @param lpProcName Pointer to a null-terminated string containing the function name
 * @return Address of the exported function, or NULL if the function is not found
 * 
 * @note Uses hash-based resolution to avoid plaintext API names in this wrapper
 * @note The actual GetProcAddress call uses plaintext function names as normal
 * @note Useful for resolving functions when you only need a few and don't want to
 *       parse the entire export table manually
 */
FARPROC WINAPI GetProcAddress_PEB(HMODULE hModule, LPCSTR lpProcName) {
    // Dynamically resolve kernel32.dll by hash
    HMODULE hKernel32 = CLoaderDynGetModuleByAdler32(HASH_kernel32_dll);

    // Dynamically resolve GetProcAddress function by hash
    pGetProcAddress dyn_GetProcAddress = (pGetProcAddress)CLoaderDynGetProcAddressByAdler32(hKernel32, HASH_GetProcAddress);

    // Call the actual GetProcAddress function
    return dyn_GetProcAddress(hModule, lpProcName);
}

#endif  // CLOADER_H
