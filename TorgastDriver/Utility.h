#pragma once
#include "Definitions.h"
#define FunctionTemplate 	template <typename Function> NTSTATUS

typedef union
{
    QWORD Value;

    struct
    {
        QWORD PE : 1;
        QWORD MP : 1;
        QWORD EM : 1;
        QWORD TS : 1;
        QWORD ET : 1;
        QWORD NE : 1;
        QWORD Reserved1 : 10;
        QWORD WP : 1;
        QWORD Reserved2 : 1;
        QWORD AM : 1;
        QWORD Reserved3 : 10;
        QWORD NW : 1;
        QWORD CD : 1;
        QWORD PG : 1;
    }CR3;

}uCR3;

/// <summary>
/// Useful kernel shit
/// </summary>
namespace Utility
{
    void		EnableWriteProtection();
    void		DisableWriteProtection();
    PVOID		GetSystemModuleExport(const LPCSTR& ModuleName, const LPCSTR& RoutineName);
    QWORD		GetSystemModuleBase(const LPCSTR& ModuleName);
    NTSTATUS	        CopyVirtualMemory(const PEPROCESS& Process, const PVOID& Source, const PVOID& Target, const SIZE_T& Size);
    NTSTATUS            ImportHook(const QWORD& Base, const PVOID& NewFunction, const char* HookName);
    PEPROCESS		GetEPROCESS(const HANDLE& ProcID);
    HANDLE_TABLE*	GetHandleTable(const PEPROCESS& Process);
    const char*         GetProcessNameFromPid(const HANDLE& pid);
    bool                KernelOpenProcess(PHANDLE Handle, HANDLE ProcID);
    QWORD               FindCodeCave(PVOID Module, size_t len, QWORD Begin);
    QWORD               CodeCaveJmp(const LPCSTR& ModuleName, PVOID HookFunction);


    FunctionTemplate ExecuteInProcess(const Function& Lambda, const HANDLE& ProcID)
    {
        LogCall();
        PEPROCESS Process;

        if (NT_SUCCESS(PsLookupProcessByProcessId(ProcID, &Process)))
        {
            KAPC_STATE apc;
            KeStackAttachProcess(Process, &apc);
            Log("Attatching to Process");
            Lambda();
            Log("Detaching from Process");
            KeUnstackDetachProcess(&apc);
            ObDereferenceObject(Process);
            return STATUS_SUCCESS;
        }
        else
        {
            LogErrorInfo("Couldn't Find Process");
            return STATUS_INVALID_PARAMETER_2;
        }
    }


    FunctionTemplate ExecuteInProcess(const Function& Lambda, const PEPROCESS& Process)
    {
        LogCall();
        KAPC_STATE apc;
        KeStackAttachProcess(Process, &apc);
        LogInfo("Attatching to Process");
        Lambda();
        LogInfo("Detaching from Process");
        KeUnstackDetachProcess(&apc);
        return STATUS_SUCCESS;
    }
}