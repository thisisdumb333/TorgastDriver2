#pragma once
#include "Undocumented.h"
#define Log(format, ...) DbgPrint("[*]  "  format "\n", __VA_ARGS__)
#define LogCall() DbgPrint("[*] %s called\n", __FUNCTION__)
#define LogInfo(format, ...) DbgPrint("\t\t\t\t\t\t[+]  "  format "\n", __VA_ARGS__)
#define LogError(format, ...) DbgPrint("[-] "  format "\n", __VA_ARGS__)
#define LogErrorInfo(format, ...) DbgPrint("\t\t\t\t\t\t[-] "  format "\n", __VA_ARGS__)
#define EXTERN_C extern "C"


typedef enum _MemoryType
{
	READ, WRITE
}MemoryType;

typedef enum _Operation
{
	GET_PROCESS_BASE, COPY,
}Operation;

typedef struct _MemoryOperation
{
	MemoryType         OperationType;
	DWORD			   TargetProcID;
	UINT_PTR		   TargetAddress;
	UINT_PTR		   BufferAddress;
	SIZE_T			   BufferSize;
	LONG			   Status;
}MemoryOperation, * pMemoryOperation;

typedef struct PROCESS_BASE
{
	DWORD TargetProcID;
	UINT_PTR SectionBase;
}PROCESS_BASE;


typedef struct _KernelRequest
{
	Operation           Operation;
	union
	{
		MemoryOperation Memory;
		PROCESS_BASE ProcessBase;
	};
}KernelRequest, * pKernelRequest;

typedef NTSTATUS(NTAPI* tIOCTLControl)         (PDEVICE_OBJECT Device, PIRP Irp);
EXTERN_C NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);
EXTERN_C NTKERNELAPI NTSTATUS NTAPI ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
EXTERN_C NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(IN  PEPROCESS FromProcess, IN  CONST PVOID FromAddress, IN  PEPROCESS ToProcess, OUT PVOID ToAddress, IN  SIZE_T BufferSize, IN  KPROCESSOR_MODE PreviousMode, OUT PSIZE_T NumberOfBytesCopied);
EXTERN_C NTKERNELAPI PUCHAR   NTAPI PsGetProcessImageFileName( PEPROCESS Process);
EXTERN_C NTKERNELAPI PVOID    NTAPI RtlFindExportedRoutineByName(IN PVOID ImageBase, IN PCCH RoutineName);
EXTERN_C NTKERNELAPI PPEB     NTAPI PsGetProcessPeb(IN PEPROCESS Process);
EXTERN_C NTKERNELAPI NTSTATUS NTAPI ObReferenceObjectByName(PUNICODE_STRING objectName, ULONG attributes, PACCESS_STATE accessState, ACCESS_MASK desiredAccess, POBJECT_TYPE objectType, KPROCESSOR_MODE accessMode, PVOID parseContext, PVOID* object);
