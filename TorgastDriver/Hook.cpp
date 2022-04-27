#include "Hook.h"
#pragma warning (disable: 4244 4838)

 void Hook::MemoryHandler(pKernelRequest Request)
{
	//LogCall();


	PEPROCESS targetProcess;
	NTSTATUS status;

	MemoryOperation operation = Request->Memory;

	switch (operation.OperationType)
	{
	case MemoryType::READ:
	{

		if (NT_SUCCESS(status = PsLookupProcessByProcessId((HANDLE)operation.TargetProcID, &targetProcess)))
		{
			if (NT_SUCCESS(status = KeReadVirtualMemory(targetProcess, (PVOID)operation.TargetAddress, (PVOID)operation.BufferAddress, operation.BufferSize)))
			{
				//LogInfo("Sucessfully completed Request-");
			}
			else
			{
				LogErrorInfo("Failed to complete function [0x%x], arguements: [%p], [%p], [%d]", status, operation.TargetAddress, operation.BufferAddress, operation.BufferSize);
			}
			ObDereferenceObject(targetProcess);
		}
		else
		{
			LogErrorInfo("Failed to lookup function 0x%x,", status);
		}
		Request->Memory.Status = status;
		break;
	}
	case MemoryType::WRITE:
	{
		if (NT_SUCCESS(status = PsLookupProcessByProcessId((HANDLE)operation.TargetProcID, &targetProcess)))
		{
			if (NT_SUCCESS(status = KeWriteVirtualMemory(targetProcess, (PVOID)operation.TargetAddress, (PVOID)operation.BufferAddress, operation.BufferSize)))
			{
				//LogInfo("Sucessfully completed Request");
			}
			else
			{
				LogErrorInfo("Failed to complete request [0x%x], arguements: [%p], [%p], [%d]", status, operation.TargetAddress, operation.BufferAddress, operation.BufferSize);
			}
			ObDereferenceObject(targetProcess);
		}
		else
		{
			LogErrorInfo("Failed to lookup function 0x%x,", status);
		}
		Request->Memory.Status = status;
		break;
	}
	default:
	{
		Request->Memory.Status = STATUS_INVALID_PARAMETER;
		break;
	}
	}
	return;
}


/// <summary>
/// Communication via hooked function, by denying BE access to the driver they can't integrity check it.
/// </summary>
/// <param name="Param"></param>
/// <returns></returns>
NTSTATUS Hook::CommunicationHook(PVOID Param)
{
	auto Request = (pKernelRequest)(Param);
	NTSTATUS Status = STATUS_SUCCESS;
	switch (Request->Operation)
	{
	case COPY:
		MemoryHandler(Request);
		break;
	case GET_PROCESS_BASE:
		
		PEPROCESS targetProcess;
		if (NT_SUCCESS(Status = PsLookupProcessByProcessId((HANDLE)Request->ProcessBase.TargetProcID, &targetProcess)))
		{
			Request->ProcessBase.SectionBase = (UINT_PTR)PsGetProcessSectionBaseAddress(targetProcess);
			ObfDereferenceObject(targetProcess);

		}
		break;
	default:
		break;
	}

	return Status;
}

NTSTATUS Hook::KeReadVirtualMemory(PEPROCESS Process, PVOID SourceAddres, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;
	return MmCopyVirtualMemory(Process, SourceAddres, PsGetCurrentProcess(), TargetAddress, Size, UserMode, &Bytes);
}

NTSTATUS Hook::KeWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddres, PVOID TargetAddress, SIZE_T Size)
{
	SIZE_T Bytes;
	return MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddres, Process, TargetAddress, Size, UserMode, &Bytes);
}

/// <summary>
/// Same as a usermode hook, except instead of VirtualProtect, we edit the CR0 register
/// </summary>
/// <param name="TargetModuleName"></param>
/// <param name="TargetFunctionName"></param>
/// <param name="HookFunction"></param>
/// <returns></returns>
NTSTATUS Hook::HookKernelFunction(const LPCSTR& TargetModuleName, const LPCSTR& TargetFunctionName, PVOID HookFunction)
{
	if (!HookFunction)
	{
		LogErrorInfo("Invalid HookFunction");
		return STATUS_INVALID_ADDRESS;
	}

	auto* Function = reinterpret_cast<PVOID*>(Utility::GetSystemModuleExport(TargetModuleName, TargetFunctionName));

	LogInfo("Function address: [%p]", Function);
	if (!Function)
	{
		LogErrorInfo("Invalid Target Function or Target Module");
		return STATUS_INVALID_ADDRESS;
	}

	BYTE Hook[]
	{ 0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	//movabs r10, address
	  0x41, 0xFF, 0xE2,												//jmp r10
	  0x00, 0x00 , 0x00, };											//Unused bytes

	memcpy((PVOID)((UINT64)Hook + 0x2), &HookFunction, sizeof(PVOID));

	Utility::DisableWriteProtection();
	RtlCopyMemory(Function, &Hook, sizeof(Hook));
	Utility::EnableWriteProtection();
							
	LogInfo("Hooked %s", TargetFunctionName);

	return STATUS_SUCCESS;
}

/// <summary>
/// You need to hook 2 functions if your going to try to use these for ObRegisterCallbacks,
/// 3 if you want to also have a communication method
/// </summary>
/// <returns></returns>
NTSTATUS Hook::InitHook()
{
	Log("Creating communication hook..");
	LPCSTR TargetModule = "\\SystemRoot\\System32\\drivers\\dxgkrnl.sys";

	LPCSTR TargetFunction = "NtOpenCompositionSurfaceSectionInfo";

	HookKernelFunction(TargetModule, TargetFunction, &Hook::CommunicationHook);

	Log("Intializing callbacks");

	BE::HookPreCallback  = Utility::CodeCaveJmp("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", &BE::BEPreCallBackOperation);

	auto ImageLoadNotify = Utility::CodeCaveJmp("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", &Hook::ImageNotifyRoutine);

	if (BE::HookPreCallback == NULL || ImageLoadNotify == NULL)
	{
		LogErrorInfo("Jmps were NULL");
		return STATUS_UNSUCCESSFUL;
	}

	LogInfo("Callback: [%p], ImageLoadNotifyRoutine: [%p]", BE::HookPreCallback, ImageLoadNotify);

	PsSetLoadImageNotifyRoutine(reinterpret_cast<PLOAD_IMAGE_NOTIFY_ROUTINE>(ImageLoadNotify));
	
	 
	return STATUS_SUCCESS;
}



NTSTATUS NTAPI BE::BEPostCallBackOperation(PVOID Param, PVOID Param2)
{
	UNREFERENCED_PARAMETER(Param);
	UNREFERENCED_PARAMETER(Param2);

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI BE::BEPreCallBackOperation(PVOID Param, PVOID Param2)
{
	UNREFERENCED_PARAMETER(Param);
	UNREFERENCED_PARAMETER(Param2);

	const char* SourceName = (const char*)Utility::GetProcessNameFromPid(PsGetCurrentProcessId());
	
	//Filters out openprocess called by any of our protected programs

	if (strcmp(SourceName, "MugenJinFuu-x8") == 0)
	{
		return 0;
	}
	else if (strcmp(SourceName, "ReClass.NET.ex") == 0)
	{
		return 0;
	}
	else if (strcmp(SourceName, "GH Injector - ") == 0)
	{
		return 0;
	}
	else
	{
		return OriginalPreCallback(Param, (POB_PRE_OPERATION_INFORMATION)Param2);
	}
}

/// <summary>
/// This function works, but Battle eye does a usermode check, which is why its currently unusued.
/// I am unsure if the usermode check is from their own syscall or not. If its just NtOpenProcess
/// You could just hook that and return STATUS_ACCESS_DENIED to it. However, they also dynamically import it, so its a lot of extra steps..
/// </summary>
/// <param name="CallbackRegistration"></param>
/// <param name="RegistrationHandle"></param>
/// <returns></returns>
NTSTATUS NTAPI BE::BEObRegisterCallbacks(POB_CALLBACK_REGISTRATION CallbackRegistration, PVOID* RegistrationHandle)
{  
	Log("BattleEye Called ObRegisterCallbacks");
	UNREFERENCED_PARAMETER(CallbackRegistration);
	UNREFERENCED_PARAMETER(RegistrationHandle);


	Log("Number of registrations: [%i]", CallbackRegistration->OperationRegistrationCount);
	OriginalPreCallback = CallbackRegistration->OperationRegistration->PreOperation; //Save their operation for use later

	CallbackRegistration->OperationRegistration->PreOperation =  (POB_PRE_OPERATION_CALLBACK)HookPreCallback;
	CallbackRegistration->OperationRegistration->PostOperation = NULL;

	auto Second = CallbackRegistration->OperationRegistration + (sizeof(POB_OPERATION_REGISTRATION));

	Second->PreOperation = (POB_PRE_OPERATION_CALLBACK)HookPreCallback;
	Second->PostOperation = NULL;

	auto callbackstatus = ObRegisterCallbacks(CallbackRegistration, RegistrationHandle);
	Log("callbackstatus : %X", callbackstatus);

	return callbackstatus;
							
}

NTSTATUS NTAPI BE::BEPsSetCreateThreadNotifyRoutine(_In_ PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine) //Unlike ObRegisterCallback, BE doesn't seem to care here. It doesnt seem to care about any of its callbacks honestly.
{
	UNREFERENCED_PARAMETER(NotifyRoutine);

	Log("CreateThreadNotify Called");

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI BE::BEZwOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatus, ULONG ShareAccess, ULONG OpenOptions)
{
	UNREFERENCED_PARAMETER(FileHandle);
	UNREFERENCED_PARAMETER(DesiredAccess);
	UNREFERENCED_PARAMETER(ObjectAttributes);
	UNREFERENCED_PARAMETER(IoStatus);
	UNREFERENCED_PARAMETER(ShareAccess);
	UNREFERENCED_PARAMETER(OpenOptions);

	if (wcsstr(ObjectAttributes->ObjectName->Buffer, L"\\SystemRoot\\System32\\drivers\\dxgkrnl.sys"))
	{
		Log("Denying access to hooked driver..");
		return STATUS_ACCESS_DENIED;
	}
	else
		return ZwOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatus, ShareAccess, OpenOptions);
}


BOOLEAN NTAPI BE::BEExEnumHandleTable(HANDLE_TABLE* HandleTable, PVOID EnumHandleProcedure, PVOID EnumParameter, PHANDLE Handle)
{
	UNREFERENCED_PARAMETER(HandleTable);
	UNREFERENCED_PARAMETER(EnumHandleProcedure);
	UNREFERENCED_PARAMETER(EnumParameter);
	UNREFERENCED_PARAMETER(Handle);

	return TRUE;
}

/// <summary>
/// Setting their Pre and post operation to NULL will allow loadlibrary to work again, and BE doesn't integrity check this like they do ObRegisterCallback 
/// Its not necessary to hook RegisterFilter, this is just a proof of concept. You shouldn't really be trying to load moudules via any windows functions in the first place
/// </summary>
/// <param name="Driver"></param>
/// <param name="Registration"></param>
/// <param name="RetFilter"></param>
/// <returns></returns>
NTSTATUS FLTAPI BE::FLT::RegisterFilter(PDRIVER_OBJECT Driver, FLTREGISTRATION* Registration, PFLT_FILTER* RetFilter)
{
	UNREFERENCED_PARAMETER(Driver);
	UNREFERENCED_PARAMETER(RetFilter);
	Log("Hooking filter manager..");

	Registration->OperationRegistration->PreOperation = NULL;
	Registration->OperationRegistration->PostOperation = NULL;

	return FltRegisterFilter(Driver, (FLT_REGISTRATION*)Registration, RetFilter);
}

NTSTATUS HWID::InitializeHWID()
{
	LogCall();
	UNICODE_STRING driverDisk;
	RtlInitUnicodeString(&driverDisk, L"\\Driver\\Disk");

	PDRIVER_OBJECT driverObject = NULL;
	auto status = ObReferenceObjectByName(&driverDisk, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, 0, *IoDriverObjectType, KernelMode, nullptr, reinterpret_cast<PVOID*>(&driverObject));

	if (!NT_SUCCESS(status))
	{
		LogError("failed to get disk driver");
		RtlFreeUnicodeString(&driverDisk);
		return status;
	}

	LogInfo("Device IRP: [%p]", driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]);
	oIOCTL = driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvIOCTLDispatcher;

	return status;
}


NTSTATUS HWID::DrvIOCTLDispatcher(PDEVICE_OBJECT Device, PIRP Irp)
{
	const char* SourceName = (const char*)Utility::GetProcessNameFromPid(PsGetCurrentProcessId());
	PIO_STACK_LOCATION  irpSp;// Pointer to current stack location
	irpSp = IoGetCurrentIrpStackLocation(Irp);
	if (strcmp(SourceName, "LaunchPad.exe") == 0)
	{
		Log("Launchpad attempted to call Disk");

		if (irpSp->Parameters.DeviceIoControl.IoControlCode == 0x2d1400)
		{
			return STATUS_ACCESS_DENIED;
		}
	}
	if (strcmp(SourceName, "PlanetSide2_x6") == 0)
	{
		Log("Planetside 2 attempted to call Disk");
		if (irpSp->Parameters.DeviceIoControl.IoControlCode == 0x2d1400)
		{
			return STATUS_ACCESS_DENIED;
		}
	}		   

	return oIOCTL(Device, Irp);
}