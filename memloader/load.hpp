#pragma once
#include <windows.h>

extern unsigned char EXEbytes[];
extern size_t EXEbytesSize;

#define RVA_TO_VA(base, rva) ((BYTE*)(base) + (rva))

void loadbytes()
{
    BYTE* exeData = EXEbytes;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)exeData;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return;

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(exeData + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return;

    SIZE_T imageSize = ntHeaders->OptionalHeader.SizeOfImage;

    BYTE* imageBase = (BYTE*)VirtualAlloc((LPVOID)(ntHeaders->OptionalHeader.ImageBase), imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!imageBase)
    {
        imageBase = (BYTE*)VirtualAlloc(NULL, imageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!imageBase) return;
    }

    memcpy(imageBase, exeData, ntHeaders->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
    {
        if (section->SizeOfRawData > 0)
        {
            memcpy(imageBase + section->VirtualAddress, exeData + section->PointerToRawData, section->SizeOfRawData);
        }
    }

    ULONG_PTR delta = (ULONG_PTR)(imageBase - ntHeaders->OptionalHeader.ImageBase);
    if (delta != 0 && ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size > 0)
    {
        PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        ULONG relocSize = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
        ULONG processed = 0;

        while (processed < relocSize)
        {
            DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* list = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < count; i++)
            {
                WORD type_offset = list[i];
                WORD type = type_offset >> 12;
                WORD offset = type_offset & 0xfff;

                if (type == IMAGE_REL_BASED_HIGHLOW)
                {
                    DWORD* patchAddr = (DWORD*)(imageBase + reloc->VirtualAddress + offset);
                    *patchAddr += (DWORD)delta;
                }
                else if (type == IMAGE_REL_BASED_DIR64)
                {
                    ULONG_PTR* patchAddr = (ULONG_PTR*)(imageBase + reloc->VirtualAddress + offset);
                    *patchAddr += (ULONG_PTR)delta;
                }
            }
            processed += reloc->SizeOfBlock;
            reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
        }
    }

    if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
    {
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)(imageBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (importDesc->Name)
        {
            char* moduleName = (char*)(imageBase + importDesc->Name);
            HMODULE module = LoadLibraryA(moduleName);
            if (!module) return;

            PIMAGE_THUNK_DATA thunkILT = (PIMAGE_THUNK_DATA)(imageBase + importDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA thunkIAT = (PIMAGE_THUNK_DATA)(imageBase + importDesc->FirstThunk);

            while (thunkILT->u1.AddressOfData)
            {
                FARPROC procAddress = NULL;
                if (thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                {
                    procAddress = GetProcAddress(module, (LPCSTR)(thunkILT->u1.Ordinal & 0xffff));
                }
                else
                {
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(imageBase + thunkILT->u1.AddressOfData);
                    procAddress = GetProcAddress(module, importByName->Name);
                }
                if (!procAddress) return;

                thunkIAT->u1.Function = (ULONG_PTR)procAddress;

                thunkILT++;
                thunkIAT++;
            }
            importDesc++;
        }
    }

    FlushInstructionCache(GetCurrentProcess(), imageBase, imageSize);

    DWORD entryRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    LPTHREAD_START_ROUTINE entryPoint = (LPTHREAD_START_ROUTINE)(imageBase + entryRVA);

    HANDLE thread = CreateThread(NULL, 0, entryPoint, NULL, 0, NULL);
    if (!thread) return;

    WaitForSingleObject(thread, INFINITE);

    VirtualFree(imageBase, 0, MEM_RELEASE);
}
