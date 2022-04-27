#include "Hook.h"
/// <summary>
/// These are the big important functions that will either get you fucked asap or strip handles, but there is so much more you can do
/// </summary>
/// <param name="SystemRoutineName"></param>
/// <returns></returns>
PVOID __stdcall SystemRoutineAddress(PUNICODE_STRING SystemRoutineName)
{

//	if (wcsstr(SystemRoutineName->Buffer, L"ObRegisterCallbacks"))
//	{
//		Log("Hooking ObRegisterCallbacks..");
//		return &BE::BEObRegisterCallbacks;
//	}

//	if (wcsstr(SystemRoutineName->Buffer, L"ExEnumHandleTable"))
//	{
//		Log("Hooking handleTable..");
//		return &BE::BEExEnumHandleTable;											 
//	}

	if (wcsstr(SystemRoutineName->Buffer, L"ZwOpenFile"))
	{
		Log("Hooking ZwOpenFile..");
		return &BE::BEZwOpenFile;
	}

//	if (wcsstr(SystemRoutineName->Buffer, L"ZwQuerySystemInformation"))
//	{
//		Log("Hooking ZwQuerySystemInformation..");
//		return &BE::BEZwQuerySystemInformation;
//	}

	return MmGetSystemRoutineAddress(SystemRoutineName);
}


PVOID NTAPI HkFltGetRoutineAddress(PCSTR FltMgrRoutineName)
{

	if (strcmp(FltMgrRoutineName, "FltRegisterFilter") == 0)
	{
		Log("Hooking FltRegisterFilter..");
		return &BE::FLT::RegisterFilter;
	}

	return FltGetRoutineAddress(FltMgrRoutineName);
}

void Hook::ImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcID, PIMAGE_INFO ImageInfo)
{
	UNREFERENCED_PARAMETER(ImageInfo);
	UNREFERENCED_PARAMETER(ProcID);

	if (wcsstr(FullImageName->Buffer, L"\\BEDaisy.sys"))
	{
		Log("BEDaisy Loaded, hooking imports..");
		auto base = reinterpret_cast<QWORD>(ImageInfo->ImageBase);
		Utility::ImportHook(base, &SystemRoutineAddress, "MmGetSystemRoutineAddress");
		//Utility::ImportHook(base, &HkFltGetRoutineAddress, "FltGetRoutineAddress");
	}
}

void Entry()
{
	LogCall();
	Hook::InitHook();
	HWID::InitializeHWID();
	Log("Ready");
}



