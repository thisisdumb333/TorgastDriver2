#pragma once
#include "Definitions.h"
#include "Utility.h"
#include <ntdddisk.h>

void SpoofSerial(char* serial, bool is_smart);

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
	struct REQUEST_STRUCT
	{
		PIO_COMPLETION_ROUTINE OldRoutine;
		PVOID OldContext;
		ULONG OutputBufferLength;
		PVOID SystemBuffer;
	};

	typedef struct _IDINFO
	{
		USHORT	wGenConfig;
		USHORT	wNumCyls;
		USHORT	wReserved;
		USHORT	wNumHeads;
		USHORT	wBytesPerTrack;
		USHORT	wBytesPerSector;
		USHORT	wNumSectorsPerTrack;
		USHORT	wVendorUnique[3];
		CHAR	sSerialNumber[20];
		USHORT	wBufferType;
		USHORT	wBufferSize;
		USHORT	wECCSize;
		CHAR	sFirmwareRev[8];
		CHAR	sModelNumber[40];
		USHORT	wMoreVendorUnique;
		USHORT	wDoubleWordIO;
		struct {
			USHORT	Reserved : 8;
			USHORT	DMA : 1;
			USHORT	LBA : 1;
			USHORT	DisIORDY : 1;
			USHORT	IORDY : 1;
			USHORT	SoftReset : 1;
			USHORT	Overlap : 1;
			USHORT	Queue : 1;
			USHORT	InlDMA : 1;
		} wCapabilities;
		USHORT	wReserved1;
		USHORT	wPIOTiming;
		USHORT	wDMATiming;
		struct {
			USHORT	CHSNumber : 1;
			USHORT	CycleNumber : 1;
			USHORT	UnltraDMA : 1;
			USHORT	Reserved : 13;
		} wFieldValidity;
		USHORT	wNumCurCyls;
		USHORT	wNumCurHeads;
		USHORT	wNumCurSectorsPerTrack;
		USHORT	wCurSectorsLow;
		USHORT	wCurSectorsHigh;
		struct {
			USHORT	CurNumber : 8;
			USHORT	Multi : 1;
			USHORT	Reserved : 7;
		} wMultSectorStuff;
		ULONG	dwTotalSectors;
		USHORT	wSingleWordDMA;
		struct {
			USHORT	Mode0 : 1;
			USHORT	Mode1 : 1;
			USHORT	Mode2 : 1;
			USHORT	Reserved1 : 5;
			USHORT	Mode0Sel : 1;
			USHORT	Mode1Sel : 1;
			USHORT	Mode2Sel : 1;
			USHORT	Reserved2 : 5;
		} wMultiWordDMA;
		struct {
			USHORT	AdvPOIModes : 8;
			USHORT	Reserved : 8;
		} wPIOCapacity;
		USHORT	wMinMultiWordDMACycle;
		USHORT	wRecMultiWordDMACycle;
		USHORT	wMinPIONoFlowCycle;
		USHORT	wMinPOIFlowCycle;
		USHORT	wReserved69[11];
		struct {
			USHORT	Reserved1 : 1;
			USHORT	ATA1 : 1;
			USHORT	ATA2 : 1;
			USHORT	ATA3 : 1;
			USHORT	ATA4 : 1;
			USHORT	ATA5 : 1;
			USHORT	ATA6 : 1;
			USHORT	ATA7 : 1;
			USHORT	ATA8 : 1;
			USHORT	ATA9 : 1;
			USHORT	ATA10 : 1;
			USHORT	ATA11 : 1;
			USHORT	ATA12 : 1;
			USHORT	ATA13 : 1;
			USHORT	ATA14 : 1;
			USHORT	Reserved2 : 1;
		} wMajorVersion;
		USHORT	wMinorVersion;
		USHORT	wReserved82[6];
		struct {
			USHORT	Mode0 : 1;
			USHORT	Mode1 : 1;
			USHORT	Mode2 : 1;
			USHORT	Mode3 : 1;
			USHORT	Mode4 : 1;
			USHORT	Mode5 : 1;
			USHORT	Mode6 : 1;
			USHORT	Mode7 : 1;
			USHORT	Mode0Sel : 1;
			USHORT	Mode1Sel : 1;
			USHORT	Mode2Sel : 1;
			USHORT	Mode3Sel : 1;
			USHORT	Mode4Sel : 1;
			USHORT	Mode5Sel : 1;
			USHORT	Mode6Sel : 1;
			USHORT	Mode7Sel : 1;
		} wUltraDMA;
		USHORT	wReserved89[167];
	} IDINFO, * PIDINFO;

	static tIOCTLControl oIOCTL;
	NTSTATUS InitializeHWID();
	NTSTATUS DrvIOCTLDispatcher(PDEVICE_OBJECT Device, PIRP Irp);
	NTSTATUS CompletedStorageQuery(PDEVICE_OBJECT device_object, PIRP irp, PVOID context);
	NTSTATUS CompletedSmart(PDEVICE_OBJECT device_object, PIRP irp, PVOID context);
	void DoCompletionHook(PIRP irp, PIO_STACK_LOCATION ioc, PIO_COMPLETION_ROUTINE routine);
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
