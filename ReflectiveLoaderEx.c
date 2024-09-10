//============================================================================//
// Copyright (c) 2012, Stephen Fewer of Harmony Security
// (www.harmonysecurity.com)
// Copyright (c) 2024, wwh1004
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//     * Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
// notice, this list of conditions and the following disclaimer in the
// documentation and/or other materials provided with the distribution.
//
//     * Neither the name of Harmony Security nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//============================================================================//
#ifndef _REFLECTIVELOADEREX_C
#define _REFLECTIVELOADEREX_C
//============================================================================//
#define WIN32_LEAN_AND_MEAN
#include <intrin.h>
#include <windows.h>

#define DEREF(name) *(UINT_PTR *)(name)
#define DEREF_64(name) *(DWORD64 *)(name)
#define DEREF_32(name) *(DWORD *)(name)
#define DEREF_16(name) *(WORD *)(name)
#define DEREF_8(name) *(BYTE *)(name)

typedef HMODULE(WINAPI *LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI *GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef DWORD(NTAPI *NTFLUSHINSTRUCTIONCACHE)(HANDLE, PVOID, ULONG);

#define GETPROCADDRESS_HASH HASH_14("GetProcAddress", 0)

#define IMAGE_REL_BASED_ARM_MOV32A 5
#define IMAGE_REL_BASED_ARM_MOV32T 7

#define ARM_MOV_MASK (DWORD)(0xFBF08000)
#define ARM_MOV_MASK2 (DWORD)(0xFBF08F00)
#define ARM_MOVW 0xF2400000
#define ARM_MOVT 0xF2C00000

#ifndef REFLECTIVELOADEREX_HASH_KEY
#define REFLECTIVELOADEREX_HASH_KEY 17
#endif
//============================================================================//

__forceinline DWORD ror(DWORD d) {
  return _rotr(d, REFLECTIVELOADEREX_HASH_KEY);
}

__forceinline DWORD hash(const char *c) {
  DWORD h = 0;
  do {
    h = ror(h);
    h += *c;
  } while (*++c);

  return h;
}

#define ROR(d, shift) (((d) >> (shift)) | ((d) << (32 - (shift))))
#define HASH_ROUND(h, c) (_rotr((h), REFLECTIVELOADEREX_HASH_KEY) + (c))
#define HASH_1(s, h) HASH_ROUND((h), s[0])
#define HASH_2(s, h) HASH_ROUND(HASH_1(s, h), s[1])
#define HASH_3(s, h) HASH_ROUND(HASH_2(s, h), s[2])
#define HASH_4(s, h) HASH_ROUND(HASH_3(s, h), s[3])
#define HASH_5(s, h) HASH_ROUND(HASH_4(s, h), s[4])
#define HASH_6(s, h) HASH_ROUND(HASH_5(s, h), s[5])
#define HASH_7(s, h) HASH_ROUND(HASH_6(s, h), s[6])
#define HASH_8(s, h) HASH_ROUND(HASH_7(s, h), s[7])
#define HASH_9(s, h) HASH_ROUND(HASH_8(s, h), s[8])
#define HASH_10(s, h) HASH_ROUND(HASH_9(s, h), s[9])
#define HASH_11(s, h) HASH_ROUND(HASH_10(s, h), s[10])
#define HASH_12(s, h) HASH_ROUND(HASH_11(s, h), s[11])
#define HASH_13(s, h) HASH_ROUND(HASH_12(s, h), s[12])
#define HASH_14(s, h) HASH_ROUND(HASH_13(s, h), s[13])
#define HASH_15(s, h) HASH_ROUND(HASH_14(s, h), s[14])
#define HASH_16(s, h) HASH_ROUND(HASH_15(s, h), s[15])
//============================================================================//
typedef struct {
  WORD offset : 12;
  WORD type : 4;
} IMAGE_RELOC, *PIMAGE_RELOC;
//============================================================================//

// This is our position independent reflective DLL loader/injector
PVOID ReflectiveLoaderEx(PVOID *libraryAddress, PVOID loadLibraryA,
                         PVOID getProcAddress, PVOID virtualAlloc,
                         PVOID ntFlushInstructionCache, BOOL copyPEHeaders) {
  // the functions we need
  LOADLIBRARYA pLoadLibraryA = (LOADLIBRARYA)loadLibraryA;
  GETPROCADDRESS pGetProcAddress = (GETPROCADDRESS)getProcAddress;
  VIRTUALALLOC pVirtualAlloc = (VIRTUALALLOC)virtualAlloc;
  NTFLUSHINSTRUCTIONCACHE pNtFlushInstructionCache =
      (NTFLUSHINSTRUCTIONCACHE)ntFlushInstructionCache;

  // the initial location of this image in memory
  ULONG_PTR uiLibraryAddress = (ULONG_PTR)*libraryAddress;
  // the kernels base address and later this images newly loaded base address
  ULONG_PTR uiBaseAddress;

  // variables for processing the kernels export table
  ULONG_PTR uiAddressArray;
  ULONG_PTR uiNameArray;
  ULONG_PTR uiExportDir;

  // variables for loading this image
  ULONG_PTR uiHeaderValue;
  ULONG_PTR uiValueA;
  ULONG_PTR uiValueB;
  ULONG_PTR uiValueC;
  ULONG_PTR uiValueD;
  ULONG_PTR uiValueE;

  // STEP 1: load our image into a new permanent location in memory...

  // get the VA of the NT Header for the PE to be loaded
  uiHeaderValue =
      uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

  // allocate all the memory for the DLL to be loaded into. we can load at any
  // address because we will relocate the image. Also zeros all memory and marks
  // it as READ, WRITE and EXECUTE to avoid any problems.
  uiBaseAddress = *(ULONG_PTR *)libraryAddress = (ULONG_PTR)pVirtualAlloc(
      NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage,
      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

  // we must now copy over the headers
  uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
  uiValueB = uiLibraryAddress;
  uiValueC = uiBaseAddress;

  if (copyPEHeaders) {
    while (uiValueA--)
      *(BYTE *)uiValueC++ = *(BYTE *)uiValueB++;
  }

  // STEP 2: load in all of our sections...

  // uiValueA = the VA of the first section
  uiValueA =
      ((ULONG_PTR) &
       ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader +
           ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader);

  // itterate through all sections, loading them into memory.
  uiValueE = ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.NumberOfSections;
  while (uiValueE--) {
    // uiValueB is the VA for this section
    uiValueB =
        (uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress);

    // uiValueC if the VA for this sections data
    uiValueC = (uiLibraryAddress +
                ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData);

    // copy the section over
    uiValueD = ((PIMAGE_SECTION_HEADER)uiValueA)->SizeOfRawData;

    while (uiValueD--)
      *(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;

    // get the VA of the next section
    uiValueA += sizeof(IMAGE_SECTION_HEADER);
  }

  // STEP 3: process our images import table...

  // uiValueB = the address of the import directory
  uiValueB = (ULONG_PTR) &
             ((PIMAGE_NT_HEADERS)uiHeaderValue)
                 ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

  // we assume their is an import table to process
  // uiValueC is the first entry in the import table
  uiValueC =
      (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

  // itterate through all imports
  while (((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name) {
    // use LoadLibraryA to load the imported module into memory
    uiLibraryAddress = (ULONG_PTR)pLoadLibraryA(
        (LPCSTR)(uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name));

    // uiValueD = VA of the OriginalFirstThunk
    uiValueD = ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk;
    if (uiValueD)
      uiValueD += uiBaseAddress;

    // uiValueA = VA of the IAT (via first thunk not origionalfirstthunk)
    uiValueA =
        (uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk);
    if (!uiValueD)
      uiValueD = uiValueA;

    // itterate through all imported functions, importing by ordinal if no name
    // present
    while (DEREF(uiValueA)) {
      // sanity check uiValueD as some compilers only import by FirstThunk
      if (uiValueD &&
          ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
        // get the VA of the modules NT Header
        uiExportDir =
            uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;

        // uiNameArray = the address of the modules export directory entry
        uiNameArray =
            (ULONG_PTR) &
            ((PIMAGE_NT_HEADERS)uiExportDir)
                ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

        // get the VA of the export directory
        uiExportDir = (uiLibraryAddress +
                       ((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress);

        // get the VA for the array of addresses
        uiAddressArray =
            (uiLibraryAddress +
             ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions);

        // use the import ordinal (- export ordinal base) as an index into the
        // array of addresses
        uiAddressArray +=
            ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal) -
              ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->Base) *
             sizeof(DWORD));

        // patch in the address for this imported function
        DEREF(uiValueA) = (uiLibraryAddress + DEREF_32(uiAddressArray));
      } else {
        // get the VA of this functions import by name struct
        uiValueB = (uiBaseAddress + DEREF(uiValueA));

        // Hack for golang
        // see src/runtime/proc.go:
        // func main() {
        //   ...
        //   exit(0)
        //   for {
        //     var x *int32
        // 	   *x = 0
        //   }
        // }
        if (hash((LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name) ==
            GETPROCADDRESS_HASH) {
          // e.g. Hook ExitProcess,GetCommandLineW
          DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress;
        } else {
          // use GetProcAddress and patch in the address for this imported
          // function
          DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress(
              (HMODULE)uiLibraryAddress,
              (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name);
        }
      }
      // get the next imported function
      uiValueA += sizeof(ULONG_PTR);
      if (uiValueD)
        uiValueD += sizeof(ULONG_PTR);
    }

    // get the next import
    uiValueC += sizeof(IMAGE_IMPORT_DESCRIPTOR);
  }

  // STEP 4: process all of our images relocations...

  // calculate the base address delta and perform relocations (even if we load
  // at desired image base)
  uiLibraryAddress =
      uiBaseAddress -
      ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;

  // uiValueB = the address of the relocation directory
  uiValueB =
      (ULONG_PTR) &
      ((PIMAGE_NT_HEADERS)uiHeaderValue)
          ->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

  // check if their are any relocations present
  if (((PIMAGE_DATA_DIRECTORY)uiValueB)->Size) {
    // uiValueC is now the first entry (IMAGE_BASE_RELOCATION)
    uiValueC =
        (uiBaseAddress + ((PIMAGE_DATA_DIRECTORY)uiValueB)->VirtualAddress);

    // and we itterate through all entries...
    while (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock) {
      // uiValueA = the VA for this relocation block
      uiValueA =
          (uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress);

      // uiValueB = number of entries in this relocation block
      uiValueB = (((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock -
                  sizeof(IMAGE_BASE_RELOCATION)) /
                 sizeof(IMAGE_RELOC);

      // uiValueD is now the first entry in the current relocation block
      uiValueD = uiValueC + sizeof(IMAGE_BASE_RELOCATION);

      // we itterate through all the entries in the current block...
      while (uiValueB--) {
        // perform the relocation, skipping IMAGE_REL_BASED_ABSOLUTE as
        // required. we dont use a switch statement to avoid the compiler
        // building a jump table which would not be very position independent!
        if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64)
          *(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) +=
              uiLibraryAddress;
        else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW)
          *(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) +=
              (DWORD)uiLibraryAddress;
#ifdef _M_ARM
        // Note: On ARM, the compiler optimization /O2 seems to introduce an off
        // by one issue, possibly a code gen bug. Using /O1 instead avoids this
        // problem.
        else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_ARM_MOV32T) {
          DWORD dwInstruction;
          DWORD dwAddress;
          WORD wImm;
          // get the MOV.T instructions DWORD value (We add 4 to the offset to
          // go past the first MOV.W which handles the low word)
          dwInstruction =
              *(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset +
                         sizeof(DWORD));
          // flip the words to get the instruction as expected
          dwInstruction =
              MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
          // sanity chack we are processing a MOV instruction...
          if ((dwInstruction & ARM_MOV_MASK) == ARM_MOVT) {
            // pull out the encoded 16bit value (the high portion of the
            // address-to-relocate)
            wImm = (WORD)(dwInstruction & 0x000000FF);
            wImm |= (WORD)((dwInstruction & 0x00007000) >> 4);
            wImm |= (WORD)((dwInstruction & 0x04000000) >> 15);
            wImm |= (WORD)((dwInstruction & 0x000F0000) >> 4);
            // apply the relocation to the target address
            dwAddress = ((WORD)HIWORD(uiLibraryAddress) + wImm) & 0xFFFF;
            // now create a new instruction with the same opcode and register
            // param.
            dwInstruction = (DWORD)(dwInstruction & ARM_MOV_MASK2);
            // patch in the relocated address...
            dwInstruction |= (DWORD)(dwAddress & 0x00FF);
            dwInstruction |= (DWORD)(dwAddress & 0x0700) << 4;
            dwInstruction |= (DWORD)(dwAddress & 0x0800) << 15;
            dwInstruction |= (DWORD)(dwAddress & 0xF000) << 4;
            // now flip the instructions words and patch back into the code...
            *(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset +
                       sizeof(DWORD)) =
                MAKELONG(HIWORD(dwInstruction), LOWORD(dwInstruction));
          }
        }
#endif
        else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGH)
          *(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) +=
              HIWORD(uiLibraryAddress);
        else if (((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_LOW)
          *(WORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) +=
              LOWORD(uiLibraryAddress);

        // get the next entry in the current relocation block
        uiValueD += sizeof(IMAGE_RELOC);
      }

      // get the next entry in the relocation directory
      uiValueC = uiValueC + ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock;
    }
  }

  // STEP 5: call our images entry point

  // uiValueA = the VA of our newly loaded DLL/EXE's entry point
  uiValueA =
      (uiBaseAddress +
       ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint);

  // We must flush the instruction cache to avoid stale code being used which
  // was updated by our relocation processing.
  pNtFlushInstructionCache((HANDLE)-1, NULL, 0);

  // STEP 6: return our new entry point address so whatever called us can call
  // DllMain() if needed.
  return (PVOID)uiValueA;
}
//============================================================================//
#endif
//============================================================================//
