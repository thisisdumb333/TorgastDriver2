#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
#include <ntdef.h>
#include <windef.h>
#include <intrin.h>
#include <fltKernel.h>
#include <wingdi.h>
#include <intrin.h>

#pragma warning (disable: 4201 4022 4094 4200)
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef int BOOL;

#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_OS2_SIGNATURE 0x454E
#define IMAGE_OS2_SIGNATURE_LE 0x454C
#define IMAGE_VXD_SIGNATURE 0x454C
#define IMAGE_NT_SIGNATURE 0x00004550

#define IMAGE_SIZEOF_SHORT_NAME 8

#define IMAGE_FIRST_SECTION(ntheader) ((PIMAGE_SECTION_HEADER) ((ULONG_PTR)ntheader + FIELD_OFFSET(IMAGE_NT_HEADERS,OptionalHeader) + ((PIMAGE_NT_HEADERS)(ntheader))->FileHeader.SizeOfOptionalHeader))
typedef unsigned __int64 QWORD;
typedef struct _IMAGE_SECTION_HEADER {
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;
    WORD e_cblp;
    WORD e_cp;
    WORD e_crlc;
    WORD e_cparhdr;
    WORD e_minalloc;
    WORD e_maxalloc;
    WORD e_ss;
    WORD e_sp;
    WORD e_csum;
    WORD e_ip;
    WORD e_cs;
    WORD e_lfarlc;
    WORD e_ovno;
    WORD e_res[4];
    WORD e_oemid;
    WORD e_oeminfo;
    WORD e_res2[10];
    LONG e_lfanew;
} IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;

typedef struct _IMAGE_OS2_HEADER {
    WORD ne_magic;
    CHAR ne_ver;
    CHAR ne_rev;
    WORD ne_enttab;
    WORD ne_cbenttab;
    LONG ne_crc;
    WORD ne_flags;
    WORD ne_autodata;
    WORD ne_heap;
    WORD ne_stack;
    LONG ne_csip;
    LONG ne_sssp;
    WORD ne_cseg;
    WORD ne_cmod;
    WORD ne_cbnrestab;
    WORD ne_segtab;
    WORD ne_rsrctab;
    WORD ne_restab;
    WORD ne_modtab;
    WORD ne_imptab;
    LONG ne_nrestab;
    WORD ne_cmovent;
    WORD ne_align;
    WORD ne_cres;
    BYTE ne_exetyp;
    BYTE ne_flagsothers;
    WORD ne_pretthunks;
    WORD ne_psegrefbytes;
    WORD ne_swaparea;
    WORD ne_expver;
} IMAGE_OS2_HEADER, * PIMAGE_OS2_HEADER;

typedef struct _IMAGE_VXD_HEADER {
    WORD e32_magic;
    BYTE e32_border;
    BYTE e32_worder;
    DWORD e32_level;
    WORD e32_cpu;
    WORD e32_os;
    DWORD e32_ver;
    DWORD e32_mflags;
    DWORD e32_mpages;
    DWORD e32_startobj;
    DWORD e32_eip;
    DWORD e32_stackobj;
    DWORD e32_esp;
    DWORD e32_pagesize;
    DWORD e32_lastpagesize;
    DWORD e32_fixupsize;
    DWORD e32_fixupsum;
    DWORD e32_ldrsize;
    DWORD e32_ldrsum;
    DWORD e32_objtab;
    DWORD e32_objcnt;
    DWORD e32_objmap;
    DWORD e32_itermap;
    DWORD e32_rsrctab;
    DWORD e32_rsrccnt;
    DWORD e32_restab;
    DWORD e32_enttab;
    DWORD e32_dirtab;
    DWORD e32_dircnt;
    DWORD e32_fpagetab;
    DWORD e32_frectab;
    DWORD e32_impmod;
    DWORD e32_impmodcnt;
    DWORD e32_impproc;
    DWORD e32_pagesum;
    DWORD e32_datapage;
    DWORD e32_preload;
    DWORD e32_nrestab;
    DWORD e32_cbnrestab;
    DWORD e32_nressum;
    DWORD e32_autodata;
    DWORD e32_debuginfo;
    DWORD e32_debuglen;
    DWORD e32_instpreload;
    DWORD e32_instdemand;
    DWORD e32_heapsize;
    BYTE e32_res3[12];
    DWORD e32_winresoff;
    DWORD e32_winreslen;
    WORD e32_devid;
    WORD e32_ddkver;
} IMAGE_VXD_HEADER, * PIMAGE_VXD_HEADER;


typedef struct _IMAGE_FILE_HEADER {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, * PIMAGE_IMPORT_BY_NAME;

#define IMAGE_SIZEOF_FILE_HEADER 20

#define IMAGE_FILE_RELOCS_STRIPPED 0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE 0x0002
#define IMAGE_FILE_LINE_NUMS_STRIPPED 0x0004
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED 0x0008
#define IMAGE_FILE_AGGRESIVE_WS_TRIM 0x0010
#define IMAGE_FILE_LARGE_ADDRESS_AWARE 0x0020
#define IMAGE_FILE_BYTES_REVERSED_LO 0x0080
#define IMAGE_FILE_32BIT_MACHINE 0x0100
#define IMAGE_FILE_DEBUG_STRIPPED 0x0200
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400
#define IMAGE_FILE_NET_RUN_FROM_SWAP 0x0800
#define IMAGE_FILE_SYSTEM 0x1000
#define IMAGE_FILE_DLL 0x2000
#define IMAGE_FILE_UP_SYSTEM_ONLY 0x4000
#define IMAGE_FILE_BYTES_REVERSED_HI 0x8000

#define IMAGE_FILE_MACHINE_UNKNOWN 0
#define IMAGE_FILE_MACHINE_I386 0x014c
#define IMAGE_FILE_MACHINE_R3000 0x0162
#define IMAGE_FILE_MACHINE_R4000 0x0166
#define IMAGE_FILE_MACHINE_R10000 0x0168
#define IMAGE_FILE_MACHINE_WCEMIPSV2 0x0169
#define IMAGE_FILE_MACHINE_ALPHA 0x0184
#define IMAGE_FILE_MACHINE_SH3 0x01a2
#define IMAGE_FILE_MACHINE_SH3DSP 0x01a3
#define IMAGE_FILE_MACHINE_SH3E 0x01a4
#define IMAGE_FILE_MACHINE_SH4 0x01a6
#define IMAGE_FILE_MACHINE_SH5 0x01a8
#define IMAGE_FILE_MACHINE_ARM 0x01c0
#define IMAGE_FILE_MACHINE_ARMV7 0x01c4
#define IMAGE_FILE_MACHINE_ARMNT 0x01c4
#define IMAGE_FILE_MACHINE_ARM64 0xaa64
#define IMAGE_FILE_MACHINE_THUMB 0x01c2
#define IMAGE_FILE_MACHINE_AM33 0x01d3
#define IMAGE_FILE_MACHINE_POWERPC 0x01F0
#define IMAGE_FILE_MACHINE_POWERPCFP 0x01f1
#define IMAGE_FILE_MACHINE_IA64 0x0200
#define IMAGE_FILE_MACHINE_MIPS16 0x0266
#define IMAGE_FILE_MACHINE_ALPHA64 0x0284
#define IMAGE_FILE_MACHINE_MIPSFPU 0x0366
#define IMAGE_FILE_MACHINE_MIPSFPU16 0x0466
#define IMAGE_FILE_MACHINE_AXP64 IMAGE_FILE_MACHINE_ALPHA64
#define IMAGE_FILE_MACHINE_TRICORE 0x0520
#define IMAGE_FILE_MACHINE_CEF 0x0CEF
#define IMAGE_FILE_MACHINE_EBC 0x0EBC
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#define IMAGE_FILE_MACHINE_M32R 0x9041
#define IMAGE_FILE_MACHINE_CEE 0xc0ee

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef struct _IMAGE_OPTIONAL_HEADER {

    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_ROM_OPTIONAL_HEADER {
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD BaseOfBss;
    DWORD GprMask;
    DWORD CprMask[4];
    DWORD GpValue;
} IMAGE_ROM_OPTIONAL_HEADER, * PIMAGE_ROM_OPTIONAL_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD Magic;
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    ULONGLONG ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

#define IMAGE_SIZEOF_ROM_OPTIONAL_HEADER 56
#define IMAGE_SIZEOF_STD_OPTIONAL_HEADER 28
#define IMAGE_SIZEOF_NT_OPTIONAL32_HEADER 224
#define IMAGE_SIZEOF_NT_OPTIONAL64_HEADER 240

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10b
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_ROM_OPTIONAL_HDR_MAGIC 0x107

#ifdef _WIN64
typedef IMAGE_OPTIONAL_HEADER64 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER64 PIMAGE_OPTIONAL_HEADER;
#define IMAGE_SIZEOF_NT_OPTIONAL_HEADER IMAGE_SIZEOF_NT_OPTIONAL64_HEADER
#define IMAGE_NT_OPTIONAL_HDR_MAGIC IMAGE_NT_OPTIONAL_HDR64_MAGIC
#else  /* _WIN64 */
typedef IMAGE_OPTIONAL_HEADER32 IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32 PIMAGE_OPTIONAL_HEADER;
#define IMAGE_SIZEOF_NT_OPTIONAL_HEADER IMAGE_SIZEOF_NT_OPTIONAL32_HEADER
#define IMAGE_NT_OPTIONAL_HDR_MAGIC IMAGE_NT_OPTIONAL_HDR32_MAGIC
#endif /* _WIN64 */

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;  // PBYTE 
        ULONGLONG Function;         // PDWORD
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64* PIMAGE_THUNK_DATA64;


typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED* PIMAGE_IMPORT_DESCRIPTOR;
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_ROM_HEADERS {
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_ROM_OPTIONAL_HEADER OptionalHeader;
} IMAGE_ROM_HEADERS, * PIMAGE_ROM_HEADERS;

#ifdef _WIN64
typedef IMAGE_NT_HEADERS64 IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS64 PIMAGE_NT_HEADERS;
#else  /* _WIN64 */
typedef IMAGE_NT_HEADERS32 IMAGE_NT_HEADERS;
typedef PIMAGE_NT_HEADERS32 PIMAGE_NT_HEADERS;
#endif /* _WIN64 */



typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemMirrorMemoryInformation,
    SystemPerformanceTraceInformation,
    SystemObsolete0,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemPlugPlayBusInformation,
    SystemDockInformation,
    SystemPowerInformationNative,
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation,
    SystemTimeSlipNotification,
    SystemSessionCreate,
    SystemSessionDetach,
    SystemSessionInformation,
    SystemRangeStartInformation,
    SystemVerifierInformation,
    SystemAddVerifier,
    SystemSessionProcessesInformation,
    SystemLoadGdiDriverInSystemSpaceInformation,
    SystemNumaProcessorMap,
    SystemPrefetcherInformation,
    SystemExtendedProcessInformation,
    SystemRecommendedSharedDataAlignment,
    SystemComPlusPackage,
    SystemNumaAvailableMemory,
    SystemProcessorPowerInformation,
    SystemEmulationBasicInformation,
    SystemEmulationProcessorInformation,
    SystemExtendedHandleInformation,
    SystemLostDelayedWriteInformation,
    SystemBigPoolInformation,
    SystemSessionPoolTagInformation,
    SystemSessionMappedViewInformation,
    SystemHotpatchInformation,
    SystemObjectSecurityMode,
    SystemWatchDogTimerHandler,
    SystemWatchDogTimerInformation,
    SystemLogicalProcessorInformation,
    SystemWow64SharedInformationObsolete,
    SystemRegisterFirmwareTableInformationHandler,
    SystemFirmwareTableInformation,
    SystemModuleInformationEx,
    SystemVerifierTriageInformation,
    SystemSuperfetchInformation,
    SystemMemoryListInformation,
    SystemFileCacheInformationEx,
    SystemThreadPriorityClientIdInformation,
    SystemProcessorIdleCycleTimeInformation,
    SystemVerifierCancellationInformation,
    SystemProcessorPowerInformationEx,
    SystemRefTraceInformation,
    SystemSpecialPoolInformation,
    SystemProcessIdInformation,
    SystemErrorPortInformation,
    SystemBootEnvironmentInformation,
    SystemHypervisorInformation,
    SystemVerifierInformationEx,
    SystemTimeZoneInformation,
    SystemImageFileExecutionOptionsInformation,
    SystemCoverageInformation,
    SystemPrefetchPathInformation,
    SystemVerifierFaultsInformation,
    MaxSystemInfoClass,
} SYSTEM_INFORMATION_CLASS;

typedef struct RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoudOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef unsigned short WORD;
typedef struct _KEXECUTE_OPTIONS
{
    ULONG ExecuteDisable : 1;
    ULONG ExecuteEnable : 1;
    ULONG DisableThunkEmulation : 1;
    ULONG Permanent : 1;
    ULONG ExecuteDispatchEnable : 1;
    ULONG ImageDispatchEnable : 1;
    ULONG Spare : 2;
} KEXECUTE_OPTIONS, * PKEXECUTE_OPTIONS;

typedef struct _KGDTENTRY
{
    WORD LimitLow;
    WORD BaseLow;
    ULONG HighWord;
} KGDTENTRY, * PKGDTENTRY;

typedef struct _KIDTENTRY
{
    WORD Offset;
    WORD Selector;
    WORD Access;
    WORD ExtendedOffset;
} KIDTENTRY, * PKIDTENTRY;


typedef struct RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];

}RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

#ifdef _WIN64
#define HANDLE_LOW_BITS (PAGE_SHIFT - 4)
#define HANDLE_HIGH_BITS (PAGE_SHIFT - 3)
#else
#define HANDLE_LOW_BITS (PAGE_SHIFT - 3)
#define HANDLE_HIGH_BITS (PAGE_SHIFT - 2)
#endif
#define HANDLE_TAG_BITS (2)
#define HANDLE_INDEX_BITS (HANDLE_LOW_BITS + 2*HANDLE_HIGH_BITS)
#define KERNEL_FLAG_BITS (sizeof(PVOID)*8 - HANDLE_INDEX_BITS - HANDLE_TAG_BITS)

typedef union _EXHANDLE
{
    struct
    {
        int TagBits : 2;
        int Index : 30;
    } u;
    void* GenericHandleOverlay;
    ULONG_PTR Value;
} EXHANDLE, * PEXHANDLE;

//0x8 bytes (sizeof)
struct _EX_PUSH_LOCK
{
    union
    {
        struct
        {
            ULONGLONG Locked : 1;                                             //0x0
            ULONGLONG Waiting : 1;                                            //0x0
            ULONGLONG Waking : 1;                                             //0x0
            ULONGLONG MultipleShared : 1;                                     //0x0
            ULONGLONG Shared : 60;                                            //0x0
        };
        ULONGLONG Value;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
};

//0x40 bytes (sizeof)
struct _HANDLE_TABLE_FREE_LIST
{
    struct _EX_PUSH_LOCK FreeListLock;                                      //0x0
    union HANDLE_TABLE_ENTRY* FirstFreeHandleEntry;                        //0x8
    union HANDLE_TABLE_ENTRY* LastFreeHandleEntry;                         //0x10
    LONG HandleCount;                                                       //0x18
    ULONG HighWaterMark;                                                    //0x1c
};

//0x80 bytes (sizeof)
typedef struct _HANDLE_TABLE
{
    ULONG NextHandleNeedingPool;                                            //0x0
    LONG ExtraInfoPages;                                                    //0x4
    volatile ULONGLONG TableCode;                                           //0x8
    struct _EPROCESS* QuotaProcess;                                         //0x10
    struct _LIST_ENTRY HandleTableList;                                     //0x18
    ULONG UniqueProcessId;                                                  //0x28
    union
    {
        ULONG Flags;
        //0x2c
        struct
        {
            UCHAR StrictFIFO : 1;                                             //0x2c
            UCHAR EnableHandleExceptions : 1;                                 //0x2c
            UCHAR Rundown : 1;                                                //0x2c
            UCHAR Duplicated : 1;                                             //0x2c
            UCHAR RaiseUMExceptionOnInvalidHandleClose : 1;                   //0x2c
        };
    };
    struct _EX_PUSH_LOCK HandleContentionEvent;                             //0x30
    struct _EX_PUSH_LOCK HandleTableLock;                                   //0x38
    union
    {
        struct _HANDLE_TABLE_FREE_LIST FreeLists[1];                        //0x40
        struct
        {
            UCHAR ActualEntry[32];                                          //0x40
            struct _HANDLE_TRACE_DEBUG_INFO* DebugInfo;                     //0x60
        };
    };
}HANDLE_TABLE, *PHANDLE_TABLE;


//0x4 bytes (sizeof)
union _KSTACK_COUNT
{
    LONG Value;                                                             //0x0
    ULONG State : 3;                                                          //0x0
    ULONG StackCount : 29;                                                    //0x0
};
//0xa8 bytes (sizeof)
struct _KAFFINITY_EX
{
    USHORT Count;                                                           //0x0
    USHORT Size;                                                            //0x2
    ULONG Reserved;                                                         //0x4
    ULONGLONG Bitmap[20];                                                   //0x8
};
// 0x1 bytes(sizeof)

struct KPROCESS
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    struct _LIST_ENTRY ProfileListHead;                                     //0x18
    ULONGLONG DirectoryTableBase;                                           //0x28
    struct _LIST_ENTRY ThreadListHead;                                      //0x30
    ULONG ProcessLock;                                                      //0x40
    ULONG ProcessTimerDelay;                                                //0x44
    ULONGLONG DeepFreezeStartTime;                                          //0x48
    struct _KAFFINITY_EX Affinity;                                          //0x50
    struct _LIST_ENTRY ReadyListHead;                                       //0xf8
    struct _SINGLE_LIST_ENTRY SwapListEntry;                                //0x108
    volatile struct _KAFFINITY_EX ActiveProcessors;                         //0x110
    union
    {
        struct
        {
            ULONG AutoAlignment : 1;                                          //0x1b8
            ULONG DisableBoost : 1;                                           //0x1b8
            ULONG DisableQuantum : 1;                                         //0x1b8
            ULONG DeepFreeze : 1;                                             //0x1b8
            ULONG TimerVirtualization : 1;                                    //0x1b8
            ULONG CheckStackExtents : 1;                                      //0x1b8
            ULONG CacheIsolationEnabled : 1;                                  //0x1b8
            ULONG PpmPolicy : 3;                                              //0x1b8
            ULONG VaSpaceDeleted : 1;                                         //0x1b8
            ULONG ReservedFlags : 21;                                         //0x1b8
        };
        volatile LONG ProcessFlags;                                         //0x1b8
    };
    ULONG ActiveGroupsMask;                                                 //0x1bc
    CHAR BasePriority;                                                      //0x1c0
    CHAR QuantumReset;                                                      //0x1c1
    CHAR Visited;                                                           //0x1c2
    BYTE Flags;                                                              //0x1c3
    USHORT ThreadSeed[20];                                                  //0x1c4
    USHORT IdealProcessor[20];                                              //0x1ec
    USHORT IdealNode[20];                                                   //0x214
    USHORT IdealGlobalNode;                                                 //0x23c
    USHORT Spare1;                                                          //0x23e
    union _KSTACK_COUNT StackCount;                                 //0x240
    struct _LIST_ENTRY ProcessListEntry;                                    //0x248
    ULONGLONG CycleTime;                                                    //0x258
    ULONGLONG ContextSwitches;                                              //0x260
    struct _KSCHEDULING_GROUP* SchedulingGroup;                             //0x268
    ULONG FreezeCount;                                                      //0x270
    ULONG KernelTime;                                                       //0x274
    ULONG UserTime;                                                         //0x278
    ULONG ReadyTime;                                                        //0x27c
    ULONGLONG UserDirectoryTableBase;                                       //0x280
    UCHAR AddressPolicy;                                                    //0x288
    UCHAR Spare2[71];                                                       //0x289
    VOID* InstrumentationCallback;                                          //0x2d0
    union
    {
        ULONGLONG SecureHandle;                                             //0x2d8
        struct
        {
            ULONGLONG SecureProcess : 1;                                      //0x2d8
            ULONGLONG Unused : 1;                                             //0x2d8
        } Flags;                                                            //0x2d8
    } SecureState;                                                          //0x2d8
};

//0x8 bytes (sizeof)
struct _SE_AUDIT_PROCESS_CREATION_INFO
{
    struct _UNICODE_STRING* ImageFileName;                         //0x0
};

//0x20 bytes (sizeof)
struct _ALPC_PROCESS_CONTEXT
{
    struct _EX_PUSH_LOCK Lock;                                              //0x0
    struct _LIST_ENTRY ViewListHead;                                        //0x8
    volatile ULONGLONG PagedPoolQuotaCache;                                 //0x18
};
//0x8 bytes (sizeof)
struct _RTL_AVL_TREE
{
    struct _RTL_BALANCED_NODE* Root;                                        //0x0
};

//0x8 bytes (sizeof)
struct _EX_FAST_REF
{
    union
    {
        VOID* Object;                                                       //0x0
        ULONGLONG RefCnt : 4;                                                 //0x0
        ULONGLONG Value;                                                    //0x0
    };
};

//0x1 bytes (sizeof)
struct _PS_PROTECTION
{
    union
    {
        UCHAR Level;                                                        //0x0
        struct
        {
            UCHAR Type : 3;                                                   //0x0
            UCHAR Audit : 1;                                                  //0x0
            UCHAR Signer : 4;                                                 //0x0
        };
    };
};

struct _JOBOBJECT_WAKE_FILTER
{
    ULONG HighEdgeFilter;                                                   //0x0
    ULONG LowEdgeFilter;                                                    //0x4
};

//0x30 bytes (sizeof)
struct _PS_PROCESS_WAKE_INFORMATION
{
    ULONGLONG NotificationChannel;                                          //0x0
    ULONG WakeCounters[7];                                                  //0x8
    struct _JOBOBJECT_WAKE_FILTER WakeFilter;                               //0x24
    ULONG NoWakeCounter;                                                    //0x2c
};

//0x8 bytes (sizeof)
union _PS_INTERLOCKED_TIMER_DELAY_VALUES
{
    ULONGLONG DelayMs : 30;                                                   //0x0
    ULONGLONG CoalescingWindowMs : 30;                                        //0x0
    ULONGLONG Reserved : 1;                                                   //0x0
    ULONGLONG NewTimerWheel : 1;                                              //0x0
    ULONGLONG Retry : 1;                                                      //0x0
    ULONGLONG Locked : 1;                                                     //0x0
    ULONGLONG All;                                                          //0x0
};
//0x4 bytes (sizeof)
struct _MMSUPPORT_FLAGS
{
    union
    {
        struct
        {
            UCHAR WorkingSetType : 3;                                         //0x0
            UCHAR Reserved0 : 3;                                              //0x0
            UCHAR MaximumWorkingSetHard : 1;                                  //0x0
            UCHAR MinimumWorkingSetHard : 1;                                  //0x0
            UCHAR SessionMaster : 1;                                          //0x1
            UCHAR TrimmerState : 2;                                           //0x1
            UCHAR Reserved : 1;                                               //0x1
            UCHAR PageStealers : 4;                                           //0x1
        };
        USHORT u1;                                                          //0x0
    };
    UCHAR MemoryPriority;                                                   //0x2
    union
    {
        struct
        {
            UCHAR WsleDeleted : 1;                                            //0x3
            UCHAR SvmEnabled : 1;                                             //0x3
            UCHAR ForceAge : 1;                                               //0x3
            UCHAR ForceTrim : 1;                                              //0x3
            UCHAR NewMaximum : 1;                                             //0x3
            UCHAR CommitReleaseState : 2;                                     //0x3
        };
        UCHAR u2;                                                           //0x3
    };
};

//0xc0 bytes (sizeof)
struct _MMSUPPORT_INSTANCE
{
    ULONG NextPageColor;                                                    //0x0
    ULONG PageFaultCount;                                                   //0x4
    ULONGLONG TrimmedPageCount;                                             //0x8
    struct _MMWSL_INSTANCE* VmWorkingSetList;                               //0x10
    struct _LIST_ENTRY WorkingSetExpansionLinks;                            //0x18
    ULONGLONG AgeDistribution[8];                                           //0x28
    struct _KGATE* ExitOutswapGate;                                         //0x68
    ULONGLONG MinimumWorkingSetSize;                                        //0x70
    ULONGLONG WorkingSetLeafSize;                                           //0x78
    ULONGLONG WorkingSetLeafPrivateSize;                                    //0x80
    ULONGLONG WorkingSetSize;                                               //0x88
    ULONGLONG WorkingSetPrivateSize;                                        //0x90
    ULONGLONG MaximumWorkingSetSize;                                        //0x98
    ULONGLONG PeakWorkingSetSize;                                           //0xa0
    ULONG HardFaultCount;                                                   //0xa8
    USHORT LastTrimStamp;                                                   //0xac
    USHORT PartitionId;                                                     //0xae
    ULONGLONG SelfmapLock;                                                  //0xb0
    struct _MMSUPPORT_FLAGS Flags;                                          //0xb8
};

//0x80 bytes (sizeof)
struct _MMSUPPORT_SHARED
{
    volatile LONG WorkingSetLock;                                           //0x0
    LONG GoodCitizenWaiting;                                                //0x4
    ULONGLONG ReleasedCommitDebt;                                           //0x8
    ULONGLONG ResetPagesRepurposedCount;                                    //0x10
    VOID* WsSwapSupport;                                                    //0x18
    VOID* CommitReleaseContext;                                             //0x20
    VOID* AccessLog;                                                        //0x28
    volatile ULONGLONG ChargedWslePages;                                    //0x30
    ULONGLONG ActualWslePages;                                              //0x38
    ULONGLONG WorkingSetCoreLock;                                           //0x40
    VOID* ShadowMapping;                                                    //0x48
};

//0x140 bytes (sizeof)
struct _MMSUPPORT_FULL
{
    struct _MMSUPPORT_INSTANCE Instance;                                    //0x0
    struct _MMSUPPORT_SHARED Shared;                                        //0xc0
};

typedef struct EPROCESS
{
    struct KPROCESS Pcb;                                                   //0x0
    struct _EX_PUSH_LOCK ProcessLock;                                       //0x2e0
    VOID* UniqueProcessId;                                                  //0x2e8
    struct _LIST_ENTRY ActiveProcessLinks;                                  //0x2f0
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x300
    union
    {
        ULONG Flags2;                                                       //0x308
        struct
        {
            ULONG JobNotReallyActive : 1;                                     //0x308
            ULONG AccountingFolded : 1;                                       //0x308
            ULONG NewProcessReported : 1;                                     //0x308
            ULONG ExitProcessReported : 1;                                    //0x308
            ULONG ReportCommitChanges : 1;                                    //0x308
            ULONG LastReportMemory : 1;                                       //0x308
            ULONG ForceWakeCharge : 1;                                        //0x308
            ULONG CrossSessionCreate : 1;                                     //0x308
            ULONG NeedsHandleRundown : 1;                                     //0x308
            ULONG RefTraceEnabled : 1;                                        //0x308
            ULONG PicoCreated : 1;                                            //0x308
            ULONG EmptyJobEvaluated : 1;                                      //0x308
            ULONG DefaultPagePriority : 3;                                    //0x308
            ULONG PrimaryTokenFrozen : 1;                                     //0x308
            ULONG ProcessVerifierTarget : 1;                                  //0x308
            ULONG RestrictSetThreadContext : 1;                               //0x308
            ULONG AffinityPermanent : 1;                                      //0x308
            ULONG AffinityUpdateEnable : 1;                                   //0x308
            ULONG PropagateNode : 1;                                          //0x308
            ULONG ExplicitAffinity : 1;                                       //0x308
            ULONG ProcessExecutionState : 2;                                  //0x308
            ULONG EnableReadVmLogging : 1;                                    //0x308
            ULONG EnableWriteVmLogging : 1;                                   //0x308
            ULONG FatalAccessTerminationRequested : 1;                        //0x308
            ULONG DisableSystemAllowedCpuSet : 1;                             //0x308
            ULONG ProcessStateChangeRequest : 2;                              //0x308
            ULONG ProcessStateChangeInProgress : 1;                           //0x308
            ULONG InPrivate : 1;                                              //0x308
        };
    };
    union
    {
        ULONG Flags;                                                        //0x30c
        struct
        {
            ULONG CreateReported : 1;                                         //0x30c
            ULONG NoDebugInherit : 1;                                         //0x30c
            ULONG ProcessExiting : 1;                                         //0x30c
            ULONG ProcessDelete : 1;                                          //0x30c
            ULONG ManageExecutableMemoryWrites : 1;                           //0x30c
            ULONG VmDeleted : 1;                                              //0x30c
            ULONG OutswapEnabled : 1;                                         //0x30c
            ULONG Outswapped : 1;                                             //0x30c
            ULONG FailFastOnCommitFail : 1;                                   //0x30c
            ULONG Wow64VaSpace4Gb : 1;                                        //0x30c
            ULONG AddressSpaceInitialized : 2;                                //0x30c
            ULONG SetTimerResolution : 1;                                     //0x30c
            ULONG BreakOnTermination : 1;                                     //0x30c
            ULONG DeprioritizeViews : 1;                                      //0x30c
            ULONG WriteWatch : 1;                                             //0x30c
            ULONG ProcessInSession : 1;                                       //0x30c
            ULONG OverrideAddressSpace : 1;                                   //0x30c
            ULONG HasAddressSpace : 1;                                        //0x30c
            ULONG LaunchPrefetched : 1;                                       //0x30c
            ULONG Background : 1;                                             //0x30c
            ULONG VmTopDown : 1;                                              //0x30c
            ULONG ImageNotifyDone : 1;                                        //0x30c
            ULONG PdeUpdateNeeded : 1;                                        //0x30c
            ULONG VdmAllowed : 1;                                             //0x30c
            ULONG ProcessRundown : 1;                                         //0x30c
            ULONG ProcessInserted : 1;                                        //0x30c
            ULONG DefaultIoPriority : 3;                                      //0x30c
            ULONG ProcessSelfDelete : 1;                                      //0x30c
            ULONG SetTimerResolutionLink : 1;                                 //0x30c
        };
    };
    union _LARGE_INTEGER CreateTime;                                        //0x310
    ULONGLONG ProcessQuotaUsage[2];                                         //0x318
    ULONGLONG ProcessQuotaPeak[2];                                          //0x328
    ULONGLONG PeakVirtualSize;                                              //0x338
    ULONGLONG VirtualSize;                                                  //0x340
    struct _LIST_ENTRY SessionProcessLinks;                                 //0x348
    union
    {
        VOID* ExceptionPortData;                                            //0x358
        ULONGLONG ExceptionPortValue;                                       //0x358
        ULONGLONG ExceptionPortState : 3;                                     //0x358
    };
    struct _EX_FAST_REF Token;                                              //0x360
    ULONGLONG MmReserved;                                                   //0x368
    struct _EX_PUSH_LOCK AddressCreationLock;                               //0x370
    struct _EX_PUSH_LOCK PageTableCommitmentLock;                           //0x378
    struct _ETHREAD* RotateInProgress;                                      //0x380
    struct _ETHREAD* ForkInProgress;                                        //0x388
    struct _EJOB* volatile CommitChargeJob;                                 //0x390
    struct _RTL_AVL_TREE CloneRoot;                                         //0x398
    volatile ULONGLONG NumberOfPrivatePages;                                //0x3a0
    volatile ULONGLONG NumberOfLockedPages;                                 //0x3a8
    VOID* Win32Process;                                                     //0x3b0
    struct _EJOB* volatile Job;                                             //0x3b8
    VOID* SectionObject;                                                    //0x3c0
    VOID* SectionBaseAddress;                                               //0x3c8
    ULONG Cookie;                                                           //0x3d0
    struct _PAGEFAULT_HISTORY* WorkingSetWatch;                             //0x3d8
    VOID* Win32WindowStation;                                               //0x3e0
    VOID* InheritedFromUniqueProcessId;                                     //0x3e8
    volatile ULONGLONG OwnerProcessId;                                      //0x3f0
    struct _PEB* Peb;                                                       //0x3f8
    struct _MM_SESSION_SPACE* Session;                                      //0x400
    VOID* Spare1;                                                           //0x408
    struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;                               //0x410
    struct _HANDLE_TABLE* ObjectTable;                                      //0x418
    VOID* DebugPort;                                                        //0x420
    struct _EWOW64PROCESS* WoW64Process;                                    //0x428
    VOID* DeviceMap;                                                        //0x430
    VOID* EtwDataSource;                                                    //0x438
    ULONGLONG PageDirectoryPte;                                             //0x440
    struct _FILE_OBJECT* ImageFilePointer;                                  //0x448
    UCHAR ImageFileName[15];                                                //0x450
    UCHAR PriorityClass;                                                    //0x45f
    VOID* SecurityPort;                                                     //0x460
    struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;      //0x468
    struct _LIST_ENTRY JobLinks;                                            //0x470
    VOID* HighestUserAddress;                                               //0x480
    struct _LIST_ENTRY ThreadListHead;                                      //0x488
    volatile ULONG ActiveThreads;                                           //0x498
    ULONG ImagePathHash;                                                    //0x49c
    ULONG DefaultHardErrorProcessing;                                       //0x4a0
    LONG LastThreadExitStatus;                                              //0x4a4
    struct _EX_FAST_REF PrefetchTrace;                                      //0x4a8
    VOID* LockedPagesList;                                                  //0x4b0
    union _LARGE_INTEGER ReadOperationCount;                                //0x4b8
    union _LARGE_INTEGER WriteOperationCount;                               //0x4c0
    union _LARGE_INTEGER OtherOperationCount;                               //0x4c8
    union _LARGE_INTEGER ReadTransferCount;                                 //0x4d0
    union _LARGE_INTEGER WriteTransferCount;                                //0x4d8
    union _LARGE_INTEGER OtherTransferCount;                                //0x4e0
    ULONGLONG CommitChargeLimit;                                            //0x4e8
    volatile ULONGLONG CommitCharge;                                        //0x4f0
    volatile ULONGLONG CommitChargePeak;                                    //0x4f8
    struct _MMSUPPORT_FULL Vm;                                              //0x500
    struct _LIST_ENTRY MmProcessLinks;                                      //0x640
    ULONG ModifiedPageCount;                                                //0x650
    LONG ExitStatus;                                                        //0x654
    struct _RTL_AVL_TREE VadRoot;                                           //0x658
    VOID* VadHint;                                                          //0x660
    ULONGLONG VadCount;                                                     //0x668
    volatile ULONGLONG VadPhysicalPages;                                    //0x670
    ULONGLONG VadPhysicalPagesLimit;                                        //0x678
    struct _ALPC_PROCESS_CONTEXT AlpcContext;                               //0x680
    struct _LIST_ENTRY TimerResolutionLink;                                 //0x6a0
    struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;               //0x6b0
    ULONG RequestedTimerResolution;                                         //0x6b8
    ULONG SmallestTimerResolution;                                          //0x6bc
    union _LARGE_INTEGER ExitTime;                                          //0x6c0
    struct _INVERTED_FUNCTION_TABLE* InvertedFunctionTable;                 //0x6c8
    struct _EX_PUSH_LOCK InvertedFunctionTableLock;                         //0x6d0
    ULONG ActiveThreadsHighWatermark;                                       //0x6d8
    ULONG LargePrivateVadCount;                                             //0x6dc
    struct _EX_PUSH_LOCK ThreadListLock;                                    //0x6e0
    VOID* WnfContext;                                                       //0x6e8
    struct _EJOB* ServerSilo;                                               //0x6f0
    UCHAR SignatureLevel;                                                   //0x6f8
    UCHAR SectionSignatureLevel;                                            //0x6f9
    struct _PS_PROTECTION Protection;                                       //0x6fa
    UCHAR HangCount : 3;                                                      //0x6fb
    UCHAR GhostCount : 3;                                                     //0x6fb
    UCHAR PrefilterException : 1;                                             //0x6fb
    union
    {
        ULONG Flags3;                                                       //0x6fc
        struct
        {
            ULONG Minimal : 1;                                                //0x6fc
            ULONG ReplacingPageRoot : 1;                                      //0x6fc
            ULONG Crashed : 1;                                                //0x6fc
            ULONG JobVadsAreTracked : 1;                                      //0x6fc
            ULONG VadTrackingDisabled : 1;                                    //0x6fc
            ULONG AuxiliaryProcess : 1;                                       //0x6fc
            ULONG SubsystemProcess : 1;                                       //0x6fc
            ULONG IndirectCpuSets : 1;                                        //0x6fc
            ULONG RelinquishedCommit : 1;                                     //0x6fc
            ULONG HighGraphicsPriority : 1;                                   //0x6fc
            ULONG CommitFailLogged : 1;                                       //0x6fc
            ULONG ReserveFailLogged : 1;                                      //0x6fc
            ULONG SystemProcess : 1;                                          //0x6fc
            ULONG HideImageBaseAddresses : 1;                                 //0x6fc
            ULONG AddressPolicyFrozen : 1;                                    //0x6fc
            ULONG ProcessFirstResume : 1;                                     //0x6fc
            ULONG ForegroundExternal : 1;                                     //0x6fc
            ULONG ForegroundSystem : 1;                                       //0x6fc
            ULONG HighMemoryPriority : 1;                                     //0x6fc
            ULONG EnableProcessSuspendResumeLogging : 1;                      //0x6fc
            ULONG EnableThreadSuspendResumeLogging : 1;                       //0x6fc
            ULONG SecurityDomainChanged : 1;                                  //0x6fc
            ULONG SecurityFreezeComplete : 1;                                 //0x6fc
            ULONG VmProcessorHost : 1;                                        //0x6fc
        };
    };
    LONG DeviceAsid;                                                        //0x700
    VOID* SvmData;                                                          //0x708
    struct _EX_PUSH_LOCK SvmProcessLock;                                    //0x710
    ULONGLONG SvmLock;                                                      //0x718
    struct _LIST_ENTRY SvmProcessDeviceListHead;                            //0x720
    ULONGLONG LastFreezeInterruptTime;                                      //0x730
    struct _PROCESS_DISK_COUNTERS* DiskCounters;                            //0x738
    VOID* PicoContext;                                                      //0x740
    VOID* EnclaveTable;                                                     //0x748
    ULONGLONG EnclaveNumber;                                                //0x750
    struct _EX_PUSH_LOCK EnclaveLock;                                       //0x758
    ULONG HighPriorityFaultsAllowed;                                        //0x760
    struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;                       //0x768
    VOID* VmContext;                                                        //0x770
    ULONGLONG SequenceNumber;                                               //0x778
    ULONGLONG CreateInterruptTime;                                          //0x780
    ULONGLONG CreateUnbiasedInterruptTime;                                  //0x788
    ULONGLONG TotalUnbiasedFrozenTime;                                      //0x790
    ULONGLONG LastAppStateUpdateTime;                                       //0x798
    ULONGLONG LastAppStateUptime : 61;                                        //0x7a0
    ULONGLONG LastAppState : 3;                                               //0x7a0
    volatile ULONGLONG SharedCommitCharge;                                  //0x7a8
    struct _EX_PUSH_LOCK SharedCommitLock;                                  //0x7b0
    struct _LIST_ENTRY SharedCommitLinks;                                   //0x7b8
    union
    {
        struct
        {
            ULONGLONG AllowedCpuSets;                                       //0x7c8
            ULONGLONG DefaultCpuSets;                                       //0x7d0
        };
        struct
        {
            ULONGLONG* AllowedCpuSetsIndirect;                              //0x7c8
            ULONGLONG* DefaultCpuSetsIndirect;                              //0x7d0
        };
    };
    VOID* DiskIoAttribution;                                                //0x7d8
    VOID* DxgProcess;                                                       //0x7e0
    ULONG Win32KFilterSet;                                                  //0x7e8
    volatile union _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay;     //0x7f0
    volatile ULONG KTimerSets;                                              //0x7f8
    volatile ULONG KTimer2Sets;                                             //0x7fc
    volatile ULONG ThreadTimerSets;                                         //0x800
    ULONGLONG VirtualTimerListLock;                                         //0x808
    struct _LIST_ENTRY VirtualTimerListHead;                                //0x810
    union
    {
        struct _WNF_STATE_NAME WakeChannel;                                 //0x820
        struct _PS_PROCESS_WAKE_INFORMATION WakeInfo;                       //0x820
    };
    union
    {
        ULONG MitigationFlags;                                              //0x850
        struct
        {
            ULONG ControlFlowGuardEnabled : 1;                                //0x850
            ULONG ControlFlowGuardExportSuppressionEnabled : 1;               //0x850
            ULONG ControlFlowGuardStrict : 1;                                 //0x850
            ULONG DisallowStrippedImages : 1;                                 //0x850
            ULONG ForceRelocateImages : 1;                                    //0x850
            ULONG HighEntropyASLREnabled : 1;                                 //0x850
            ULONG StackRandomizationDisabled : 1;                             //0x850
            ULONG ExtensionPointDisable : 1;                                  //0x850
            ULONG DisableDynamicCode : 1;                                     //0x850
            ULONG DisableDynamicCodeAllowOptOut : 1;                          //0x850
            ULONG DisableDynamicCodeAllowRemoteDowngrade : 1;                 //0x850
            ULONG AuditDisableDynamicCode : 1;                                //0x850
            ULONG DisallowWin32kSystemCalls : 1;                              //0x850
            ULONG AuditDisallowWin32kSystemCalls : 1;                         //0x850
            ULONG EnableFilteredWin32kAPIs : 1;                               //0x850
            ULONG AuditFilteredWin32kAPIs : 1;                                //0x850
            ULONG DisableNonSystemFonts : 1;                                  //0x850
            ULONG AuditNonSystemFontLoading : 1;                              //0x850
            ULONG PreferSystem32Images : 1;                                   //0x850
            ULONG ProhibitRemoteImageMap : 1;                                 //0x850
            ULONG AuditProhibitRemoteImageMap : 1;                            //0x850
            ULONG ProhibitLowILImageMap : 1;                                  //0x850
            ULONG AuditProhibitLowILImageMap : 1;                             //0x850
            ULONG SignatureMitigationOptIn : 1;                               //0x850
            ULONG AuditBlockNonMicrosoftBinaries : 1;                         //0x850
            ULONG AuditBlockNonMicrosoftBinariesAllowStore : 1;               //0x850
            ULONG LoaderIntegrityContinuityEnabled : 1;                       //0x850
            ULONG AuditLoaderIntegrityContinuity : 1;                         //0x850
            ULONG EnableModuleTamperingProtection : 1;                        //0x850
            ULONG EnableModuleTamperingProtectionNoInherit : 1;               //0x850
            ULONG RestrictIndirectBranchPrediction : 1;                       //0x850
            ULONG IsolateSecurityDomain : 1;                                  //0x850
        } MitigationFlagsValues;                                            //0x850
    };
    union
    {
        ULONG MitigationFlags2;                                             //0x854
        struct
        {
            ULONG EnableExportAddressFilter : 1;                              //0x854
            ULONG AuditExportAddressFilter : 1;                               //0x854
            ULONG EnableExportAddressFilterPlus : 1;                          //0x854
            ULONG AuditExportAddressFilterPlus : 1;                           //0x854
            ULONG EnableRopStackPivot : 1;                                    //0x854
            ULONG AuditRopStackPivot : 1;                                     //0x854
            ULONG EnableRopCallerCheck : 1;                                   //0x854
            ULONG AuditRopCallerCheck : 1;                                    //0x854
            ULONG EnableRopSimExec : 1;                                       //0x854
            ULONG AuditRopSimExec : 1;                                        //0x854
            ULONG EnableImportAddressFilter : 1;                              //0x854
            ULONG AuditImportAddressFilter : 1;                               //0x854
            ULONG DisablePageCombine : 1;                                     //0x854
            ULONG SpeculativeStoreBypassDisable : 1;                          //0x854
            ULONG CetUserShadowStacks : 1;                                    //0x854
        } MitigationFlags2Values;                                           //0x854
    };
    VOID* PartitionObject;                                                  //0x858
    ULONGLONG SecurityDomain;                                               //0x860
    ULONGLONG ParentSecurityDomain;                                         //0x868
    VOID* CoverageSamplerContext;                                           //0x870
    VOID* MmHotPatchContext;                                                //0x878
}EPROCESS;

typedef struct _PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

#define RTL_MAX_DRIVE_LETTERS 32

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PWCHAR Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

#define GDI_HANDLE_BUFFER_SIZE32    34
#define GDI_HANDLE_BUFFER_SIZE64    60

#ifndef _WIN64
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE32
#else
#define GDI_HANDLE_BUFFER_SIZE GDI_HANDLE_BUFFER_SIZE64
#endif

typedef ULONG GDI_HANDLE_BUFFER32[GDI_HANDLE_BUFFER_SIZE32];
typedef ULONG GDI_HANDLE_BUFFER64[GDI_HANDLE_BUFFER_SIZE64];
typedef ULONG GDI_HANDLE_BUFFER[GDI_HANDLE_BUFFER_SIZE];


typedef struct _RTL_CRITICAL_SECTION_DEBUG {
    WORD   Type;
    WORD   CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION* CriticalSection;
    LIST_ENTRY ProcessLocksList;
    DWORD EntryCount;
    DWORD ContentionCount;
    DWORD Flags;
    WORD   CreatorBackTraceIndexHigh;
    WORD   SpareWORD;
} RTL_CRITICAL_SECTION_DEBUG, * PRTL_CRITICAL_SECTION_DEBUG, RTL_RESOURCE_DEBUG, * PRTL_RESOURCE_DEBUG;

typedef struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;

    //
    //  The following three fields control entering and exiting the critical
    //  section for the resource
    //

    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;        // from the thread's ClientId->UniqueThread
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;        // force size on 64-bit systems when packed
} RTL_CRITICAL_SECTION, * PRTL_CRITICAL_SECTION;

#define FLS_MAXIMUM_AVAILABLE 4080  
#define TLS_MINIMUM_AVAILABLE 64    

typedef struct _PEB
{
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN IsLongPathAwareProcess : 1;
        } s1;
    } u1;

    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ProcessPreviouslyThrottled : 1;
            ULONG ProcessCurrentlyThrottled : 1;
            ULONG ReservedBits0 : 25;
        } s2;
    } u2;
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    } u3;
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];

    PVOID ReadOnlySharedMemoryBase;
    PVOID SharedData; // HotpatchInformation
    PVOID* ReadOnlyStaticServerData;

    PVOID AnsiCodePageData; // PCPTABLEINFO
    PVOID OemCodePageData; // PCPTABLEINFO
    PVOID UnicodeCaseTableData; // PNLSTABLEINFO

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID* ProcessHeaps; // PHEAP

    PVOID GdiSharedHandleTable;
    PVOID ProcessStarterHelper;
    ULONG GdiDCAttributeList;

    PRTL_CRITICAL_SECTION LoaderLock;

    ULONG OSMajorVersion;
    ULONG OSMinorVersion;
    USHORT OSBuildNumber;
    USHORT OSCSDVersion;
    ULONG OSPlatformId;
    ULONG ImageSubsystem;
    ULONG ImageSubsystemMajorVersion;
    ULONG ImageSubsystemMinorVersion;
    ULONG_PTR ActiveProcessAffinityMask;
    GDI_HANDLE_BUFFER GdiHandleBuffer;
    PVOID PostProcessInitRoutine;

    PVOID TlsExpansionBitmap;
    ULONG TlsExpansionBitmapBits[32];

    ULONG SessionId;

    ULARGE_INTEGER AppCompatFlags;
    ULARGE_INTEGER AppCompatFlagsUser;
    PVOID pShimData;
    PVOID AppCompatInfo; // APPCOMPAT_EXE_DATA

    UNICODE_STRING CSDVersion;

    PVOID ActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID ProcessAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP
    PVOID SystemDefaultActivationContextData; // ACTIVATION_CONTEXT_DATA
    PVOID SystemAssemblyStorageMap; // ASSEMBLY_STORAGE_MAP

    SIZE_T MinimumStackCommit;

    PVOID* FlsCallback;
    LIST_ENTRY FlsListHead;
    PVOID FlsBitmap;
    ULONG FlsBitmapBits[FLS_MAXIMUM_AVAILABLE / (sizeof(ULONG) * 8)];
    ULONG FlsHighIndex;

    PVOID WerRegistrationData;
    PVOID WerShipAssertPtr;
    PVOID pUnused; // pContextData
    PVOID pImageHeaderHash;
    union
    {
        ULONG TracingFlags;
        struct
        {
            ULONG HeapTracingEnabled : 1;
            ULONG CritSecTracingEnabled : 1;
            ULONG LibLoaderTracingEnabled : 1;
            ULONG SpareTracingBits : 29;
        } s3;
    } u4;
    ULONGLONG CsrServerReadOnlySharedMemoryBase;
    PVOID TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    PVOID WaitOnAddressHashTable[128];
    PVOID TelemetryCoverageHeader; // REDSTONE3
    ULONG CloudFileFlags;
} PEB, * PPEB;

typedef NTSTATUS(NTAPI* tNtQueryInformationProcess) (
    HANDLE ProcHandle,
    PROCESSINFOCLASS ProcInfoClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLenth);

typedef struct _IMAGE_TLS_DIRECTORY64 {
    ULONGLONG StartAddressOfRawData;
    ULONGLONG EndAddressOfRawData;
    ULONGLONG AddressOfIndex;         // PDWORD
    ULONGLONG AddressOfCallBacks;     // PIMAGE_TLS_CALLBACK *;
    DWORD SizeOfZeroFill;
    union {
        DWORD Characteristics;
        struct {
            DWORD Reserved0 : 20;
            DWORD Alignment : 4;
            DWORD Reserved1 : 8;
        } DUMMYSTRUCTNAME;
    } DUMMYUNIONNAME;

} IMAGE_TLS_DIRECTORY64;

typedef struct _IMAGE_BASE_RELOCATION {
    DWORD   VirtualAddress;
    DWORD   SizeOfBlock;
} IMAGE_BASE_RELOCATION;

typedef struct _LDR_SERVICE_TAG_RECORD
{
    struct _LDR_SERVICE_TAG_RECORD* Next;
    ULONG ServiceTag;
} LDR_SERVICE_TAG_RECORD, * PLDR_SERVICE_TAG_RECORD;

typedef struct _LDRP_CSLIST
{
    PSINGLE_LIST_ENTRY Tail;
} LDRP_CSLIST, * PLDRP_CSLIST;

typedef enum _LDR_DDAG_STATE
{
    LdrModulesMerged = -5,
    LdrModulesInitError = -4,
    LdrModulesSnapError = -3,
    LdrModulesUnloaded = -2,
    LdrModulesUnloading = -1,
    LdrModulesPlaceHolder = 0,
    LdrModulesMapping = 1,
    LdrModulesMapped = 2,
    LdrModulesWaitingForDependencies = 3,
    LdrModulesSnapping = 4,
    LdrModulesSnapped = 5,
    LdrModulesCondensed = 6,
    LdrModulesReadyToInit = 7,
    LdrModulesInitializing = 8,
    LdrModulesReadyToRun = 9
} LDR_DDAG_STATE;

typedef struct _OBJECT_TYPE_INITIALIZER
{
    WORD Length;
    UCHAR ObjectTypeFlags;
    ULONG CaseInsensitive : 1;
    ULONG UnnamedObjectsOnly : 1;
    ULONG UseDefaultObject : 1;
    ULONG SecurityRequired : 1;
    ULONG MaintainHandleCount : 1;
    ULONG MaintainTypeList : 1;
    ULONG ObjectTypeCode;
    ULONG InvalidAttributes;
    GENERIC_MAPPING GenericMapping;
    ULONG ValidAccessMask;
    POOL_TYPE PoolType;
    ULONG DefaultPagedPoolCharge;
    ULONG DefaultNonPagedPoolCharge;
    PVOID DumpProcedure;
    LONG* OpenProcedure;
    PVOID CloseProcedure;
    PVOID DeleteProcedure;
    LONG* ParseProcedure;
    LONG* SecurityProcedure;
    LONG* QueryNameProcedure;
    UCHAR* OkayToCloseProcedure;
} OBJECT_TYPE_INITIALIZER, * POBJECT_TYPE_INITIALIZER;

typedef struct _OBJECT_TYPE
{
    ERESOURCE Mutex;
    LIST_ENTRY TypeList;
    UNICODE_STRING Name;
    PVOID DefaultObject;
    ULONG Index;
    ULONG TotalNumberOfObjects;
    ULONG TotalNumberOfHandles;
    ULONG HighWaterNumberOfObjects;
    ULONG HighWaterNumberOfHandles;
    OBJECT_TYPE_INITIALIZER TypeInfo;
    ULONG Key;
    EX_PUSH_LOCK ObjectLocks[32];
} OBJECT_TYPE, * POBJECT_TYPE;

typedef struct _LDR_DDAG_NODE
{
    LIST_ENTRY Modules;
    PLDR_SERVICE_TAG_RECORD ServiceTagList;
    ULONG LoadCount;
    ULONG LoadWhileUnloadingCount;
    ULONG LowestLink;
    union
    {
        LDRP_CSLIST Dependencies;
        SINGLE_LIST_ENTRY RemovalLink;
    };
    LDRP_CSLIST IncomingDependencies;
    LDR_DDAG_STATE State;
    SINGLE_LIST_ENTRY CondenseLink;
    ULONG PreorderNumber;
} LDR_DDAG_NODE, * PLDR_DDAG_NODE;

typedef enum _LDR_DLL_LOAD_REASON
{
    LoadReasonStaticDependency,
    LoadReasonStaticForwarderDependency,
    LoadReasonDynamicForwarderDependency,
    LoadReasonDelayloadDependency,
    LoadReasonDynamicLoad,
    LoadReasonAsImageLoad,
    LoadReasonAsDataLoad,
    LoadReasonUnknown = -1
} LDR_DLL_LOAD_REASON, * PLDR_DLL_LOAD_REASON;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    union
    {
        LIST_ENTRY InInitializationOrderLinks;
        LIST_ENTRY InProgressLinks;
    };
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    union
    {
        UCHAR FlagGroup[4];
        ULONG Flags;
        struct
        {
            ULONG PackagedBinary : 1;
            ULONG MarkedForRemoval : 1;
            ULONG ImageDll : 1;
            ULONG LoadNotificationsSent : 1;
            ULONG TelemetryEntryProcessed : 1;
            ULONG ProcessStaticImport : 1;
            ULONG InLegacyLists : 1;
            ULONG InIndexes : 1;
            ULONG ShimDll : 1;
            ULONG InExceptionTable : 1;
            ULONG ReservedFlags1 : 2;
            ULONG LoadInProgress : 1;
            ULONG LoadConfigProcessed : 1;
            ULONG EntryProcessed : 1;
            ULONG ProtectDelayLoad : 1;
            ULONG ReservedFlags3 : 2;
            ULONG DontCallForThreads : 1;
            ULONG ProcessAttachCalled : 1;
            ULONG ProcessAttachFailed : 1;
            ULONG CorDeferredValidate : 1;
            ULONG CorImage : 1;
            ULONG DontRelocate : 1;
            ULONG CorILOnly : 1;
            ULONG ReservedFlags5 : 3;
            ULONG Redirected : 1;
            ULONG ReservedFlags6 : 2;
            ULONG CompatDatabaseProcessed : 1;
        } s;
    } u;
    USHORT ObsoleteLoadCount;
    USHORT TlsIndex;
    LIST_ENTRY HashLinks;
    ULONG TimeDateStamp;
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
    PVOID Lock;
    PLDR_DDAG_NODE DdagNode;
    LIST_ENTRY NodeModuleLink;
    struct _LDRP_LOAD_CONTEXT* LoadContext;
    PVOID ParentDllBase;
    PVOID SwitchBackContext;
    RTL_BALANCED_NODE BaseAddressIndexNode;
    RTL_BALANCED_NODE MappingInfoIndexNode;
    ULONG_PTR OriginalBase;
    LARGE_INTEGER LoadTime;
    ULONG BaseNameHashValue;
    LDR_DLL_LOAD_REASON LoadReason;
    ULONG ImplicitPathOptions;
    ULONG ReferenceCount;
    ULONG DependentLoadFlags;
    UCHAR SigningLevel; // Since Windows 10 RS2
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef LONG KPRIORITY, * PKPRIORITY;

extern "C" POBJECT_TYPE * IoDriverObjectType;



typedef struct _SYSTEM_THREAD {

    LARGE_INTEGER           KernelTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           CreateTime;
    ULONG                   WaitTime;
    PVOID                   StartAddress;
    CLIENT_ID               ClientId;
    KPRIORITY               Priority;
    LONG                    BasePriority;
    ULONG                   ContextSwitchCount;
    ULONG                   State;
    KWAIT_REASON            WaitReason;

} SYSTEM_THREAD, * PSYSTEM_THREAD;

typedef struct _SYSTEM_PROCESS_INFORMATION {



    ULONG                   NextEntryOffset;
    ULONG                   NumberOfThreads;
    LARGE_INTEGER           Reserved[3];
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           KernelTime;
    UNICODE_STRING          ImageName;
    KPRIORITY               BasePriority;
    HANDLE                  ProcessId;
    HANDLE                  InheritedFromProcessId;
    ULONG                   HandleCount;
    ULONG                   Reserved2[2];
    ULONG                   PrivatePageCount;
    VM_COUNTERS             VirtualMemoryCounters;
    IO_COUNTERS             IoCounters;
    SYSTEM_THREAD           Threads[0];

} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment
} KAPC_ENVIRONMENT;

typedef struct _HANDLE_TABLE_ENTRY_INFO
{
    ULONG AuditMask;
} HANDLE_TABLE_ENTRY_INFO, * PHANDLE_TABLE_ENTRY_INFO;

typedef struct _HANDLE_TABLE_ENTRY
{
    union
    {
        PVOID Object;
        ULONG ObAttributes;
        PHANDLE_TABLE_ENTRY_INFO InfoTable;
        ULONG Value;
    };
    union
    {
        ULONG GrantedAccess;
        struct
        {
            WORD GrantedAccessIndex;
            WORD CreatorBackTraceIndex;
        };
        LONG NextFreeTableEntry;
    };
} HANDLETABLE_ENTRY, * PHANDLE_TABLE_ENTRY;

typedef
VOID
(*PKNORMAL_ROUTINE) (
    IN PVOID NormalContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
    );

typedef VOID
(*PKKERNEL_ROUTINE) (
    IN struct _KAPC* Apc,
    IN OUT PKNORMAL_ROUTINE* NormalRoutine,
    IN OUT PVOID* NormalContext,
    IN OUT PVOID* SystemArgument1,
    IN OUT PVOID* SystemArgument2
    );

typedef VOID
(*PKRUNDOWN_ROUTINE) (
    IN struct _KAPC* Apc
    );

typedef struct FLTREGISTRATION {
    USHORT                                      Size;
    USHORT                                      Version;
    FLT_REGISTRATION_FLAGS                      Flags;
    FLT_CONTEXT_REGISTRATION*                   ContextRegistration;
    FLT_OPERATION_REGISTRATION*                 OperationRegistration;
    PFLT_FILTER_UNLOAD_CALLBACK                 FilterUnloadCallback;
    PFLT_INSTANCE_SETUP_CALLBACK                InstanceSetupCallback;
    PFLT_INSTANCE_QUERY_TEARDOWN_CALLBACK       InstanceQueryTeardownCallback;
    PFLT_INSTANCE_TEARDOWN_CALLBACK             InstanceTeardownStartCallback;
    PFLT_INSTANCE_TEARDOWN_CALLBACK             InstanceTeardownCompleteCallback;
    PFLT_GENERATE_FILE_NAME                     GenerateFileNameCallback;
    PFLT_NORMALIZE_NAME_COMPONENT               NormalizeNameComponentCallback;
    PFLT_NORMALIZE_CONTEXT_CLEANUP              NormalizeContextCleanupCallback;
    PFLT_TRANSACTION_NOTIFICATION_CALLBACK      TransactionNotificationCallback;
    PFLT_NORMALIZE_NAME_COMPONENT_EX            NormalizeNameComponentExCallback;
    PFLT_SECTION_CONFLICT_NOTIFICATION_CALLBACK SectionNotificationCallback;
} FLTREGISTRATION, * PFLTREGISTRATION;