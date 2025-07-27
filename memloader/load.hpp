#include <windows.h>
#include <iostream>

#define RVA_TO_VA(base, rva) ((BYTE*)(base) + (rva))

extern unsigned char EXEbytes[];
extern size_t EXEbytesSize;

void loadbytes()
{
    __try
    {
        BYTE* exeData = EXEbytes;
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)exeData;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;

        PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(exeData + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return;

        SIZE_T size = nt->OptionalHeader.SizeOfImage;
        BYTE* mem = (BYTE*)VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!mem) return;

        memcpy(mem, exeData, nt->OptionalHeader.SizeOfHeaders);

        PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++)
        {
            if (sec->SizeOfRawData)
            {
                memcpy(mem + sec->VirtualAddress, exeData + sec->PointerToRawData, sec->SizeOfRawData);
            }
        }

        ULONG_PTR delta = (ULONG_PTR)(mem - nt->OptionalHeader.ImageBase);
        if (delta && nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
        {
            PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)(mem +
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
            SIZE_T processed = 0;
            while (processed < nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
            {
                DWORD count = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                WORD* list = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
                for (DWORD i = 0; i < count; i++)
                {
                    WORD type_offset = list[i];
                    WORD type = type_offset >> 12;
                    WORD offset = type_offset & 0xFFF;
                    BYTE* addr = mem + reloc->VirtualAddress + offset;

                    if (type == IMAGE_REL_BASED_HIGHLOW)
                        *(DWORD*)addr += (DWORD)delta;
                    else if (type == IMAGE_REL_BASED_DIR64)
                        *(ULONGLONG*)addr += delta;
                }
                processed += reloc->SizeOfBlock;
                reloc = (PIMAGE_BASE_RELOCATION)((BYTE*)reloc + reloc->SizeOfBlock);
            }
        }

        if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
        {
            PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(mem +
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
            while (imp->Name)
            {
                char* modName = (char*)(mem + imp->Name);
                HMODULE lib = LoadLibraryA(modName);
                if (!lib) return;

                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(mem + imp->FirstThunk);
                PIMAGE_THUNK_DATA orig = imp->OriginalFirstThunk ?
                    (PIMAGE_THUNK_DATA)(mem + imp->OriginalFirstThunk) : thunk;

                while (orig->u1.AddressOfData)
                {
                    FARPROC proc = nullptr;
                    if (orig->u1.Ordinal & IMAGE_ORDINAL_FLAG)
                    {
                        proc = GetProcAddress(lib, (LPCSTR)(orig->u1.Ordinal & 0xFFFF));
                    }
                    else
                    {
                        PIMAGE_IMPORT_BY_NAME name = (PIMAGE_IMPORT_BY_NAME)(mem + orig->u1.AddressOfData);
                        proc = GetProcAddress(lib, name->Name);
                    }

                    if (!proc) return;
                    thunk->u1.Function = (ULONGLONG)proc;

                    ++thunk;
                    ++orig;
                }

                ++imp;
            }
        }

        FlushInstructionCache(GetCurrentProcess(), mem, size);

        DWORD epRVA = nt->OptionalHeader.AddressOfEntryPoint;
        void (*entry)() = (void(*)())(mem + epRVA);
        entry();

        VirtualFree(mem, 0, MEM_RELEASE);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        DWORD code = GetExceptionCode();
        std::cout << "[!] SEH Exception code: 0x" << std::hex << code << std::dec << std::endl;
    }
}
