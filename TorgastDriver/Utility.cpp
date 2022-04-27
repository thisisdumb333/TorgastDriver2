#include "Utility.h"
#pragma warning (disable: 6011)


PEPROCESS Utility::GetEPROCESS(const HANDLE& ProcID)
{
    PEPROCESS Process;
    return NT_SUCCESS(PsLookupProcessByProcessId(ProcID, &Process)) ? Process : NULL;
}

const char* Utility::GetProcessNameFromPid(const HANDLE& pid)
{
    PEPROCESS Process;
    if (PsLookupProcessByProcessId(pid, &Process) == STATUS_INVALID_PARAMETER)
    {
        return "pid???";
    }
    return (const char*)PsGetProcessImageFileName(Process);
}

HANDLE_TABLE* Utility::GetHandleTable(const PEPROCESS& Process)
{
    PHANDLE_TABLE table = *(PHANDLE_TABLE*)((BYTE*)Process + 0x570);

    return table;
}

NTSTATUS Utility::ImportHook(const QWORD& Base, const PVOID& NewFunction, const char* HookName)
{ 
    auto DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Base);
    auto NTHeader  = reinterpret_cast<PIMAGE_NT_HEADERS>(Base + DosHeader->e_lfanew);
    auto Import    = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(Base + NTHeader->OptionalHeader.DataDirectory[1].VirtualAddress);

    UNREFERENCED_PARAMETER(NewFunction);
    UNREFERENCED_PARAMETER(HookName);

    for (; Import->Characteristics; Import++)
    {
       auto FirstThunk    = reinterpret_cast<PIMAGE_THUNK_DATA64>(Base + Import->FirstThunk);
       auto OriginalThunk = reinterpret_cast<PIMAGE_THUNK_DATA64>(Base + Import->OriginalFirstThunk);

        for (; FirstThunk->u1.Function != NULL; OriginalThunk++, FirstThunk++)
        {
            auto name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(Base + OriginalThunk->u1.AddressOfData);

            if (strcmp(HookName, (const char*)(name->Name)) == 0)
            {
               LogInfo("Found [%s]", HookName);
               DisableWriteProtection();
               FirstThunk->u1.Function = reinterpret_cast<QWORD>(NewFunction);
               EnableWriteProtection();
               LogInfo("Hook set");
               return STATUS_SUCCESS;
            }
        }
    }
     
    LogErrorInfo("Couldn't find Import..");
    return STATUS_UNSUCCESSFUL;  
}


UINT64 Utility::GetSystemModuleBase(const LPCSTR& ModuleName)
{
    PVOID ModuleBase = NULL;
    ULONG Size       = NULL;
        
    auto Status  = ZwQuerySystemInformation(SystemModuleInformation, NULL, Size, &Size);

    if (!Size)
    {
        LogErrorInfo("ZwQuerySystemInformation Failed");
        return NULL;
    }

    auto Modules = reinterpret_cast<PRTL_PROCESS_MODULES>(ExAllocatePool(NonPagedPool, Size));

    if (Modules)
    {
        Status = ZwQuerySystemInformation(SystemModuleInformation, Modules, Size, &Size);

        auto CurrentModule = Modules->Modules;

        for (ULONG i = 0; i < Modules->NumberOfModules; i++)
        {
            //LogInfo("Loaded module : [%s]", (LPCSTR)CurrentModule[i].FullPathName);
            if (strcmp((LPCSTR)CurrentModule[i].FullPathName, ModuleName) == 0)
            {
                ModuleBase = CurrentModule[i].ImageBase;
            }
        }

        ExFreePool(Modules);

        if (ModuleBase <= NULL)
        {
            LogErrorInfo("GetModuleBase Failed");
            return NULL;
        }

        return reinterpret_cast<QWORD>(ModuleBase);
    }

    LogErrorInfo("Couldn't initialize module list");
    return NULL;
}

QWORD Utility::CodeCaveJmp(const LPCSTR& ModuleName, PVOID HookFunction)
{

    auto CodeCaveBase = Utility::FindCodeCave(reinterpret_cast<PVOID>(Utility::GetSystemModuleBase(ModuleName)), 13, NULL);

    if (!CodeCaveBase)
    {
        LogErrorInfo("Couldn't find a valid codecave section");
        return NULL;
    }

    LogInfo("Found valid code cave.. [%p]", CodeCaveBase);

    BYTE Hook[]
    { 0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	//movabs r10, address
      0x41, 0xFF, 0xE2 };											//jmp r10			

    memcpy((PVOID)((QWORD)Hook + 0x2), &HookFunction, sizeof(PVOID));

    DisableWriteProtection();
    RtlCopyMemory(reinterpret_cast<PVOID>(CodeCaveBase), &Hook, sizeof(Hook));
    EnableWriteProtection();

    return CodeCaveBase;
};



 /*
PVOID Utility::GetSystemModuleExport(const PCWSTR& ModuleName, const LPCSTR& RoutineName)
{
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"PsLoadedModuleList");

    auto ModuleList = reinterpret_cast<PLIST_ENTRY>(MmGetSystemRoutineAddress(&name));

    RtlFreeUnicodeString(&name);

    if (!ModuleList)
    {
        LogError("GetSystemModuleBase returned NULL");
        return NULL;
    }

    for (auto link = ModuleList; link != ModuleList->Blink; link = link->Flink)
    {
        PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(link, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        UNICODE_STRING name2;

        RtlInitUnicodeString(&name2, ModuleName);

        if (RtlEqualUnicodeString(&entry->BaseDllName, &name2, TRUE))
        {
            return (entry->DllBase) ? RtlFindExportedRoutineByName(entry->DllBase, RoutineName) : NULL;
        }
    }

    return NULL;
}
*/
         
PVOID Utility::GetSystemModuleExport(const LPCSTR& ModuleName, const LPCSTR& RoutineName)
{
    auto ModuleBase = GetSystemModuleBase(ModuleName);

    if (!ModuleBase)
    {
        LogErrorInfo("GetSystemModuleBase returned NULL");
        return NULL;
    }

    return RtlFindExportedRoutineByName(reinterpret_cast<PVOID>(ModuleBase), RoutineName);
}

void Utility::EnableWriteProtection()
{
    uCR3 ControlRegister;
    ControlRegister.Value = __readcr0();
    ControlRegister.CR3.WP = 0b1;
    _enable();
    __writecr0(ControlRegister.Value);
}

void Utility::DisableWriteProtection()
{
    uCR3 ControlRegister;
    ControlRegister.Value = __readcr0();
    ControlRegister.CR3.WP = 0b0;
    __writecr0(ControlRegister.Value);
    _disable();
}

NTSTATUS Utility::CopyVirtualMemory(const PEPROCESS& Process, const PVOID& Source, const PVOID& Target, const SIZE_T& Size)
{
    SIZE_T Bytes;
    auto Proc = PsGetCurrentProcess();
    return MmCopyVirtualMemory(Proc, Source, Process, Target, Size, KernelMode, &Bytes);
}


bool Utility::KernelOpenProcess(PHANDLE Handle, HANDLE ProcID)
{
    CLIENT_ID id;
    id.UniqueProcess = ProcID;
    id.UniqueThread  = NULL;

    OBJECT_ATTRIBUTES ob;

    InitializeObjectAttributes(&ob, NULL, NULL, NULL, NULL);

    if (NT_SUCCESS(ZwOpenProcess(Handle, PROCESS_ALL_ACCESS, &ob, &id)))
    {
        return true;

    }
    else
    {
        return false;
    }
}

QWORD Utility::FindCodeCave(PVOID Module, size_t len, QWORD Begin)
{
    QWORD  Start = NULL;
    size_t Size = NULL;

    auto BaseAddress = Module;

    if (!BaseAddress)
    {
        LogErrorInfo("Couldn't find BaseAddress");
        return false;
    }

    auto ImageDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(BaseAddress);
    auto ImageNTHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PBYTE>(BaseAddress) + ImageDosHeader->e_lfanew);
    auto Section = IMAGE_FIRST_SECTION(ImageNTHeader);

    for (auto i = 0; i < ImageNTHeader->FileHeader.NumberOfSections; i++, ++Section)
    {
        if (strcmp(reinterpret_cast<const char*>(Section->Name), ".text") == 0)
        {
            Start = reinterpret_cast<QWORD>(BaseAddress) + Section->PointerToRawData;
            Size = Section->SizeOfRawData;
           
        }
    }

    auto CheckForReturnOp = [&](BYTE op)
    {
        return op == 0xC2 ||      // RETN + POP
               op == 0xC3 ||      // RETN
               op == 0xCA ||      // RETF + POP
               op == 0xCB;        // RETF
    };

    QWORD match = 0;
    INT curlength = 0;
    BOOLEAN ret = FALSE;

    for (QWORD cur = (Begin ? Begin : Start); cur < Start + Size; ++cur)
    {
        if (!ret && CheckForReturnOp(*(BYTE*)cur))
        {
            ret = TRUE;
        }

        else if (ret && *(BYTE*)cur == 0xCC)
        {
            if (!match)
            {
                match = cur;
            }

            if (++curlength == len)
            {
                return match;
            }
        }

        else
        {
            match = curlength = 0;
            ret = FALSE;
        }
    }

    return match;
}
