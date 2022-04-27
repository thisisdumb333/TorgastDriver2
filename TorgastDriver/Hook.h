#pragma once
#include "Definitions.h"
#include "Utility.h"

namespace Hook
{
	void	 MemoryHandler(pKernelRequest Request);
	void	 ImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcID, PIMAGE_INFO ImageInfo);
	NTSTATUS CommunicationHook(PVOID Param);
	NTSTATUS KeReadVirtualMemory(PEPROCESS Process, PVOID SourceAddres, PVOID TargetAddress, SIZE_T Size);
	NTSTATUS KeWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddres, PVOID TargetAddress, SIZE_T Size);
	NTSTATUS HookKernelFunction(const LPCSTR& TargetModuleName, const LPCSTR& TargetFunctionName, PVOID HookFunction);
	NTSTATUS InitHook();
}

namespace HWID
{
	static tIOCTLControl oIOCTL;
	NTSTATUS InitializeHWID();
	NTSTATUS DrvIOCTLDispatcher(PDEVICE_OBJECT Device, PIRP Irp);

}


namespace BE
{
	  static   POB_PRE_OPERATION_CALLBACK OriginalPreCallback;
	  static   QWORD					  HookPreCallback; 
	  NTSTATUS NTAPI BEPostCallBackOperation(PVOID Param, PVOID Param2);
	  NTSTATUS NTAPI BEPreCallBackOperation(PVOID Param, PVOID Param2);
	  NTSTATUS NTAPI BEObRegisterCallbacks(POB_CALLBACK_REGISTRATION CallbackRegistration, PVOID* RegistrationHandle);
	  BOOLEAN  NTAPI BEExEnumHandleTable(HANDLE_TABLE* HandleTable, PVOID EnumHandleProcedure, PVOID EnumParameter, PHANDLE Handle);
	  NTSTATUS NTAPI BEPsSetCreateThreadNotifyRoutine(_In_ PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine);	   
	  NTSTATUS NTAPI BEZwOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatus, ULONG ShareAccess, ULONG OpenOptions);
	  namespace FLT
	  {
		  NTSTATUS FLTAPI RegisterFilter(PDRIVER_OBJECT Driver, FLTREGISTRATION* Registration, PFLT_FILTER* RetFilter);
	  }
}
