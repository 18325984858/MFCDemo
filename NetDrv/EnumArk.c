//
// EnumArk.c - process & driver enumeration, results streamed via UDP.
//

#include "EnumArk.h"
#include "Wsk.h"
#include "TcpLink.h"
#include "Ioctl.h"
#include <ntstrsafe.h>
#include <stdlib.h>     // _strtoui64 / strtoul for parsing put commands
#include "../Shared/NdarkLog.h"
#include "CompatPool.h"

#define LOG(fmt, ...) NDARK_LOG_INFO(fmt, ##__VA_ARGS__)
#define TAG_ARK 'krAN'

NTKERNELAPI NTSTATUS NTAPI
SeLocateProcessImageName(_In_ PEPROCESS Process,
                         _Outptr_ PUNICODE_STRING* ProcessImageName);

NTKERNELAPI NTSTATUS NTAPI
PsLookupProcessByProcessId(_In_ HANDLE ProcessId,
                           _Outptr_ PEPROCESS* Process);

NTSYSAPI NTSTATUS NTAPI
ZwOpenDirectoryObject(_Out_ PHANDLE DirectoryHandle,
                      _In_  ACCESS_MASK DesiredAccess,
                      _In_  POBJECT_ATTRIBUTES ObjectAttributes);

NTSYSAPI NTSTATUS NTAPI
ZwQueryDirectoryObject(_In_  HANDLE DirectoryHandle,
                       _Out_ PVOID Buffer,
                       _In_  ULONG Length,
                       _In_  BOOLEAN ReturnSingleEntry,
                       _In_  BOOLEAN RestartScan,
                       _Inout_ PULONG Context,
                       _Out_opt_ PULONG ReturnLength);

NTKERNELAPI NTSTATUS ObReferenceObjectByName(
    _In_      PUNICODE_STRING ObjectPath,
    _In_      ULONG           Attributes,
    _In_opt_  PACCESS_STATE   PassedAccessState,
    _In_opt_  ACCESS_MASK     DesiredAccess,
    _In_      POBJECT_TYPE    ObjectType,
    _In_      KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID         ParseContext,
    _Outptr_  PVOID*          Object);

extern POBJECT_TYPE* IoDriverObjectType;

typedef struct _ARK_OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} ARK_OBJECT_DIRECTORY_INFORMATION, *PARK_OBJECT_DIRECTORY_INFORMATION;

// ---------------------------------------------------------------------------
// Undocumented ZwQuerySystemInformation classes / structs we need.
// ---------------------------------------------------------------------------

typedef enum _ARK_SYSTEM_INFORMATION_CLASS {
    ArkSystemProcessInformation = 5,
    ArkSystemModuleInformation  = 11,
} ARK_SYSTEM_INFORMATION_CLASS;

typedef struct _ARK_SYSTEM_PROCESS_INFORMATION {
    ULONG          NextEntryOffset;
    ULONG          NumberOfThreads;
    LARGE_INTEGER  WorkingSetPrivateSize;
    ULONG          HardFaultCount;
    ULONG          NumberOfThreadsHighWatermark;
    ULONGLONG      CycleTime;
    LARGE_INTEGER  CreateTime;
    LARGE_INTEGER  UserTime;
    LARGE_INTEGER  KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY      BasePriority;
    HANDLE         ProcessId;
    HANDLE         InheritedFromProcessId;
    ULONG          HandleCount;
    ULONG          SessionId;
    // ... more fields we don't need
} ARK_SYSTEM_PROCESS_INFORMATION, *PARK_SYSTEM_PROCESS_INFORMATION;

typedef struct _ARK_RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} ARK_RTL_PROCESS_MODULE_INFORMATION, *PARK_RTL_PROCESS_MODULE_INFORMATION;

typedef struct _ARK_RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    ARK_RTL_PROCESS_MODULE_INFORMATION Modules[1];
} ARK_RTL_PROCESS_MODULES, *PARK_RTL_PROCESS_MODULES;

NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(
    _In_      ULONG  SystemInformationClass,
    _Inout_   PVOID  SystemInformation,
    _In_      ULONG  SystemInformationLength,
    _Out_opt_ PULONG ReturnLength);

// ---------------------------------------------------------------------------
// UDP helper: emit one '\n'-terminated text line to NETDRV_APP_IP:NETDRV_UDP_PORT
// using a freshly-created datagram socket per-batch (kept open across lines
// to avoid per-line bind cost).
// ---------------------------------------------------------------------------

typedef struct _ARK_UDP_CHANNEL {
    PWSK_SOCKET  Sock;
    SOCKADDR_IN  Peer;
    ULONG        SentLines;
    ULONG        FailedLines;
    SIZE_T       SentBytes;
} ARK_UDP_CHANNEL, *PARK_UDP_CHANNEL;

static NTSTATUS
ArkUdpOpenTo(_Out_ PARK_UDP_CHANNEL ch,
             _In_ UCHAR peer1,
             _In_ UCHAR peer2,
             _In_ UCHAR peer3,
             _In_ UCHAR peer4,
             _In_ USHORT peerPort,
             _In_z_ PCSTR peerName)
{
    NTSTATUS status;
    SOCKADDR_IN local = { 0 };
    SIZE_T sent = 0;

    UNREFERENCED_PARAMETER(peerName);

    RtlZeroMemory(ch, sizeof(*ch));

    status = WSK_socket(&ch->Sock, AF_INET, SOCK_DGRAM, IPPROTO_UDP,
                        WSK_FLAG_DATAGRAM_SOCKET);
    if (!NT_SUCCESS(status)) {
        LOG("ArkUdpOpen: WSK_socket failed 0x%08X", status);
        return status;
    }

    local.sin_family = AF_INET;
    local.sin_port   = 0;
    local.sin_addr.S_un.S_un_b.s_b1 = NETDRV_DRIVER_IP_B1;
    local.sin_addr.S_un.S_un_b.s_b2 = NETDRV_DRIVER_IP_B2;
    local.sin_addr.S_un.S_un_b.s_b3 = NETDRV_DRIVER_IP_B3;
    local.sin_addr.S_un.S_un_b.s_b4 = NETDRV_DRIVER_IP_B4;
    status = WSKBind(ch->Sock, (PSOCKADDR)&local);
    if (!NT_SUCCESS(status)) {
        LOG("ArkUdpOpen: bind %s failed 0x%08X", NETDRV_DRIVER_IP_A, status);
        WSK_closesocket(ch->Sock);
        ch->Sock = NULL;
        return status;
    }

    ch->Peer.sin_family = AF_INET;
    ch->Peer.sin_port   = RtlUshortByteSwap(peerPort);
    ch->Peer.sin_addr.S_un.S_un_b.s_b1 = peer1;
    ch->Peer.sin_addr.S_un.S_un_b.s_b2 = peer2;
    ch->Peer.sin_addr.S_un.S_un_b.s_b3 = peer3;
    ch->Peer.sin_addr.S_un.S_un_b.s_b4 = peer4;

    UNREFERENCED_PARAMETER(sent);
    LOG("ArkUdpOpen: local %s -> peer %s:%u", NETDRV_DRIVER_IP_A, peerName, peerPort);
    return STATUS_SUCCESS;
}

static NTSTATUS
ArkUdpOpen(_Out_ PARK_UDP_CHANNEL ch)
{
    return ArkUdpOpenTo(ch,
                        NETDRV_APP_IP_B1, NETDRV_APP_IP_B2,
                        NETDRV_APP_IP_B3, NETDRV_APP_IP_B4,
                        NETDRV_UDP_PORT,
                        NETDRV_APP_IP_A);
}

static VOID ArkUdpClose(_Inout_ PARK_UDP_CHANNEL ch);
static VOID ArkUdpSendLine(_In_ PARK_UDP_CHANNEL ch, _In_ PCSTR text);

static VOID
ArkUdpTriggerAgent(_In_z_ PCSTR command, _In_z_ PCSTR label)
{
    UNREFERENCED_PARAMETER(label);
    ARK_UDP_CHANNEL agentCh;
    NTSTATUS status = ArkUdpOpenTo(&agentCh,
                                   NETDRV_DRIVER_IP_B1, NETDRV_DRIVER_IP_B2,
                                   NETDRV_DRIVER_IP_B3, NETDRV_DRIVER_IP_B4,
                                   NETDRV_SCREEN_AGENT_PORT,
                                   NETDRV_DRIVER_IP_A);
    if (!NT_SUCCESS(status)) {
        LOG("Agent trigger %s open failed 0x%08X", label, status);
        return;
    }

    ArkUdpSendLine(&agentCh, command);
    ArkUdpClose(&agentCh);
    LOG("Agent trigger %s sent to %s:%u", label, NETDRV_DRIVER_IP_A, NETDRV_SCREEN_AGENT_PORT);
}

static VOID
ArkUdpClose(_Inout_ PARK_UDP_CHANNEL ch)
{
    if (ch->Sock) {
        LOG("ArkUdpClose: sentLines=%u failedLines=%u sentBytes=%Iu",
            ch->SentLines, ch->FailedLines, ch->SentBytes);
        WSK_closesocket(ch->Sock);
        ch->Sock = NULL;
    }
}

static VOID
ArkUdpSendLine(_In_ PARK_UDP_CHANNEL ch, _In_ PCSTR text)
{
    if (!text) return;
    SIZE_T payloadLen = strlen(text);
    if (payloadLen == 0) return;

    /* Prefer TCP when connected --- no magic prefix needed, just raw payload */
    if (TcpLinkIsConnected() || TcpLinkIsScreenConnected() || TcpLinkIsFileConnected()) {
        NTSTATUS st = TcpLinkSend(text, (ULONG)payloadLen);
        if (NT_SUCCESS(st)) {
            ++ch->SentLines;
            ch->SentBytes += payloadLen;
            return;
        }
        /* Fall through to UDP on TCP send failure */
    }

    if (!ch->Sock) { ++ch->FailedLines; return; }
    SIZE_T packetLen = NETDRV_UDP_PACKET_MAGIC_LEN + payloadLen;
    if (packetLen > 1400) {
        ++ch->FailedLines;
        LOG("ArkUdpSendLine: reject payloadLen=%Iu packetLen=%Iu", payloadLen, packetLen);
        return;
    }
    SIZE_T sent = 0;
    // Local copy because WSK requires a writable buffer locked into an MDL.
    CHAR buf[1500];
    RtlCopyMemory(buf, NETDRV_UDP_PACKET_MAGIC, NETDRV_UDP_PACKET_MAGIC_LEN);
    RtlCopyMemory(buf + NETDRV_UDP_PACKET_MAGIC_LEN, text, payloadLen);
    NTSTATUS status = WSKSendTo(ch->Sock, buf, packetLen, &sent, (PSOCKADDR)&ch->Peer);
    if (!NT_SUCCESS(status) || sent != packetLen) {
        ++ch->FailedLines;
        LOG("ArkUdpSendLine: send failed status=0x%08X sent=%Iu packetLen=%Iu text='%s'",
            status, sent, packetLen, text);
        return;
    }

    ++ch->SentLines;
    ch->SentBytes += sent;
}

//
// Wide -> narrow best-effort (non-ASCII printable becomes '?'); also
// scrubs '|' and '\n' to keep the pipe-delimited wire format intact.
//
static VOID
WideToNarrowScrub(_In_reads_(WCount) PCWSTR Wide,
                  _In_ SIZE_T WCount,
                  _Out_writes_z_(NCap) PCHAR Out,
                  _In_ SIZE_T NCap)
{
    SIZE_T j = 0;
    if (NCap == 0) return;
    for (SIZE_T i = 0; i < WCount && j + 1 < NCap; ++i) {
        WCHAR w = Wide[i];
        CHAR c;
        if (w == L'|' || w == L'\n' || w == L'\r') c = ' ';
        else if (w < 0x20 || w > 0x7E)             c = '?';
        else                                       c = (CHAR)w;
        Out[j++] = c;
    }
    Out[j] = 0;
}

// ---------------------------------------------------------------------------
// EnumProcess: emit P| lines.
// ---------------------------------------------------------------------------

NTSTATUS NetDrvEnumProcess(VOID)
{
    NTSTATUS status;
    ULONG    size = 0;
    PVOID    buf  = NULL;
    ARK_UDP_CHANNEL ch;

    PAGED_CODE();
    LOG("EnumProcess: begin");

    // Probe size; grow until happy.
    status = ZwQuerySystemInformation(ArkSystemProcessInformation, NULL, 0, &size);
    if (size == 0) {
        LOG("EnumProcess: size probe failed status=0x%08X", status);
        return STATUS_UNSUCCESSFUL;
    }

    for (int retry = 0; retry < 4; ++retry) {
        size = size + 0x4000;
        buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, TAG_ARK);
        if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
        status = ZwQuerySystemInformation(ArkSystemProcessInformation,
                                          buf, size, &size);
        if (NT_SUCCESS(status)) break;
        ExFreePoolWithTag(buf, TAG_ARK);
        buf = NULL;
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            LOG("EnumProcess: query failed status=0x%08X", status);
            return status;
        }
    }
    if (!buf) {
        LOG("EnumProcess: buffer allocation/query failed");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ArkUdpOpen(&ch);
    if (!NT_SUCCESS(status)) {
        LOG("EnumProcess: ArkUdpOpen failed status=0x%08X", status);
        ExFreePoolWithTag(buf, TAG_ARK);
        return status;
    }

    ArkUdpSendLine(&ch, "B|process\n");

    PARK_SYSTEM_PROCESS_INFORMATION p = (PARK_SYSTEM_PROCESS_INFORMATION)buf;
    ULONG count = 0;
    for (;;) {
        CHAR  line[1400];
        CHAR  imgName[128] = { 0 };
        CHAR  imgPath[800] = { 0 };
        PVOID eproc        = NULL;

        if (p->ImageName.Buffer && p->ImageName.Length > 0) {
            WideToNarrowScrub(p->ImageName.Buffer,
                              p->ImageName.Length / sizeof(WCHAR),
                              imgName, sizeof(imgName));
        } else {
            RtlStringCbCopyA(imgName, sizeof(imgName),
                (HandleToUlong(p->ProcessId) == 0) ? "Idle" : "System");
        }

        // EPROCESS lookup + full image path (skip Idle which has no EPROCESS).
        if (HandleToUlong(p->ProcessId) != 0) {
            PEPROCESS pe = NULL;
            if (NT_SUCCESS(PsLookupProcessByProcessId(p->ProcessId, &pe))) {
                eproc = pe;
                PUNICODE_STRING pImg = NULL;
                if (NT_SUCCESS(SeLocateProcessImageName(pe, &pImg)) && pImg) {
                    WideToNarrowScrub(pImg->Buffer,
                                      pImg->Length / sizeof(WCHAR),
                                      imgPath, sizeof(imgPath));
                    ExFreePool(pImg);
                }
                ObDereferenceObject(pe);
            }
        }
        if (imgPath[0] == 0) {
            RtlStringCbCopyA(imgPath, sizeof(imgPath), "-");
        }

        RtlStringCbPrintfA(line, sizeof(line),
            "P|%u|%u|%u|%p|%lld|%s|%s\n",
            HandleToUlong(p->ProcessId),
            HandleToUlong(p->InheritedFromProcessId),
            p->SessionId,
            eproc,
            p->CreateTime.QuadPart,
            imgName,
            imgPath);
        ArkUdpSendLine(&ch, line);
        ++count;

        if (p->NextEntryOffset == 0) break;
        p = (PARK_SYSTEM_PROCESS_INFORMATION)((PUCHAR)p + p->NextEntryOffset);
    }

    {
        CHAR endLine[64];
        RtlStringCbPrintfA(endLine, sizeof(endLine), "E|process|%u\n", count);
        ArkUdpSendLine(&ch, endLine);
    }

    ArkUdpClose(&ch);
    ExFreePoolWithTag(buf, TAG_ARK);
    LOG("EnumProcess: %u entries", count);
    ArkUdpTriggerAgent(NETDRV_AGENT_CMD_PROCESS, "process-enrich");
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// EnumDriver: emit D| lines.
// ---------------------------------------------------------------------------

//
// Map entry: links an ImageBase to its DRIVER_OBJECT (and friendly names).
//
typedef struct _ARK_DRVMAP_ENTRY {
    PVOID  ImageBase;
    PVOID  DriverObject;
    CHAR   ObjName[96];          // "\Driver\xxx" - ASCII scrub
    CHAR   SvcName[96];
} ARK_DRVMAP_ENTRY, *PARK_DRVMAP_ENTRY;

#define ARK_DRVMAP_CAP 1024

//
// Walk one object-manager directory (e.g. \Driver, \FileSystem), look up each
// child as a DRIVER_OBJECT via *IoDriverObjectType and record it in the map.
//
static VOID
ArkWalkDriverDirectory(_In_ PCWSTR DirPath,
                       _Inout_ PARK_DRVMAP_ENTRY Map,
                       _Inout_ PULONG Count)
{
    UNICODE_STRING dirName;
    OBJECT_ATTRIBUTES oa;
    HANDLE hDir = NULL;
    NTSTATUS status;

    RtlInitUnicodeString(&dirName, DirPath);
    InitializeObjectAttributes(&oa, &dirName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    status = ZwOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &oa);
    if (!NT_SUCCESS(status)) return;

    UCHAR  *buf = (UCHAR*)ExAllocatePool2(POOL_FLAG_PAGED, 0x4000, TAG_ARK);
    if (!buf) { ZwClose(hDir); return; }

    ULONG ctx = 0, retLen = 0;
    BOOLEAN restart = TRUE;
    while (NT_SUCCESS(ZwQueryDirectoryObject(hDir, buf, 0x4000, FALSE,
                                             restart, &ctx, &retLen)))
    {
        restart = FALSE;
        PARK_OBJECT_DIRECTORY_INFORMATION e =
            (PARK_OBJECT_DIRECTORY_INFORMATION)buf;
        for (; e->Name.Length != 0; ++e) {
            if (*Count >= ARK_DRVMAP_CAP) break;

            // Build absolute name = DirPath + "\\" + e->Name
            WCHAR full[256];
            UNICODE_STRING fullUS;
            fullUS.Buffer        = full;
            fullUS.Length        = 0;
            fullUS.MaximumLength = sizeof(full);
            if (!NT_SUCCESS(RtlAppendUnicodeToString(&fullUS, (PWSTR)DirPath)))
                continue;
            if (!NT_SUCCESS(RtlAppendUnicodeToString(&fullUS, L"\\")))
                continue;
            if (!NT_SUCCESS(RtlAppendUnicodeStringToString(&fullUS, &e->Name)))
                continue;

            PDRIVER_OBJECT drv = NULL;
            status = ObReferenceObjectByName(
                &fullUS, OBJ_CASE_INSENSITIVE, NULL, 0,
                *IoDriverObjectType, KernelMode, NULL, (PVOID*)&drv);
            if (!NT_SUCCESS(status) || !drv) continue;

            PARK_DRVMAP_ENTRY m = &Map[(*Count)++];
            RtlZeroMemory(m, sizeof(*m));
            m->ImageBase    = drv->DriverStart;
            m->DriverObject = drv;
            WideToNarrowScrub(full, fullUS.Length / sizeof(WCHAR),
                              m->ObjName, sizeof(m->ObjName));

            if (drv->DriverExtension &&
                drv->DriverExtension->ServiceKeyName.Buffer &&
                drv->DriverExtension->ServiceKeyName.Length > 0)
            {
                WideToNarrowScrub(
                    drv->DriverExtension->ServiceKeyName.Buffer,
                    drv->DriverExtension->ServiceKeyName.Length / sizeof(WCHAR),
                    m->SvcName, sizeof(m->SvcName));
            } else {
                RtlStringCbCopyA(m->SvcName, sizeof(m->SvcName), "-");
            }
            ObDereferenceObject(drv);
        }
    }

    ExFreePoolWithTag(buf, TAG_ARK);
    ZwClose(hDir);
}

static PARK_DRVMAP_ENTRY
ArkLookupDrvMap(_In_ PARK_DRVMAP_ENTRY Map, _In_ ULONG Count, _In_ PVOID ImageBase)
{
    for (ULONG i = 0; i < Count; ++i) {
        if (Map[i].ImageBase == ImageBase) return &Map[i];
    }
    return NULL;
}

NTSTATUS NetDrvEnumDriver(VOID)
{
    NTSTATUS status;
    ULONG    size = 0;
    PVOID    buf  = NULL;
    ARK_UDP_CHANNEL ch;

    PAGED_CODE();
    LOG("EnumDriver: begin");

    status = ZwQuerySystemInformation(ArkSystemModuleInformation, NULL, 0, &size);
    if (size == 0) {
        LOG("EnumDriver: size probe failed status=0x%08X", status);
        return STATUS_UNSUCCESSFUL;
    }

    for (int retry = 0; retry < 4; ++retry) {
        size = size + 0x2000;
        buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, size, TAG_ARK);
        if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
        status = ZwQuerySystemInformation(ArkSystemModuleInformation,
                                          buf, size, &size);
        if (NT_SUCCESS(status)) break;
        ExFreePoolWithTag(buf, TAG_ARK);
        buf = NULL;
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            LOG("EnumDriver: query failed status=0x%08X", status);
            return status;
        }
    }
    if (!buf) {
        LOG("EnumDriver: buffer allocation/query failed");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = ArkUdpOpen(&ch);
    if (!NT_SUCCESS(status)) {
        LOG("EnumDriver: ArkUdpOpen failed status=0x%08X", status);
        ExFreePoolWithTag(buf, TAG_ARK);
        return status;
    }

    // Build DRIVER_OBJECT lookup map.
    PARK_DRVMAP_ENTRY map = (PARK_DRVMAP_ENTRY)
        ExAllocatePool2(POOL_FLAG_PAGED,
                        sizeof(ARK_DRVMAP_ENTRY) * ARK_DRVMAP_CAP, TAG_ARK);
    ULONG mapCount = 0;
    if (map) {
        ArkWalkDriverDirectory(L"\\Driver",     map, &mapCount);
        ArkWalkDriverDirectory(L"\\FileSystem", map, &mapCount);
    }

    ArkUdpSendLine(&ch, "B|driver\n");

    PARK_RTL_PROCESS_MODULES mods = (PARK_RTL_PROCESS_MODULES)buf;
    for (ULONG i = 0; i < mods->NumberOfModules; ++i) {
        PARK_RTL_PROCESS_MODULE_INFORMATION m = &mods->Modules[i];
        m->FullPathName[sizeof(m->FullPathName) - 1] = 0;

        PCSTR drvName = (PCSTR)m->FullPathName + m->OffsetToFileName;
        PARK_DRVMAP_ENTRY de = map
            ? ArkLookupDrvMap(map, mapCount, m->ImageBase)
            : NULL;

        CHAR line[1400];
        RtlStringCbPrintfA(line, sizeof(line),
            "D|%s|%p|%u|%u|%p|%s|%s|%s\n",
            drvName,
            m->ImageBase,
            m->ImageSize,
            (ULONG)m->LoadOrderIndex,
            de ? de->DriverObject : NULL,
            de ? de->ObjName : "-",
            de ? de->SvcName : "-",
            (PCSTR)m->FullPathName);
        ArkUdpSendLine(&ch, line);
    }

    {
        CHAR endLine[64];
        RtlStringCbPrintfA(endLine, sizeof(endLine),
                           "E|driver|%u\n", mods->NumberOfModules);
        ArkUdpSendLine(&ch, endLine);
    }

    if (map) ExFreePoolWithTag(map, TAG_ARK);
    ArkUdpClose(&ch);
    LOG("EnumDriver: %u entries (%u mapped)",
        mods->NumberOfModules, mapCount);
    ExFreePoolWithTag(buf, TAG_ARK);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// File enumeration. App sends C|file|<utf8Path>\n; driver replies with
//   B|file|<pathHex>\n
//   F|<isDir 0/1>|<sizeHex>|<nameHex>\n   (one per entry)
//   E|file|<pathHex>|<count>\n
// Names and the original path are UTF-8 hex-encoded to keep '|' / '\n' out of
// the wire format (same convention as the U| process-enrich line).
// ---------------------------------------------------------------------------

// ntddk.h pulls in FILE_INFORMATION_CLASS but not the FsRtl-style FileBoth
// structure or ZwQueryDirectoryFile - both live in ntifs.h. Declare locally
// to avoid switching headers for the whole TU.
typedef struct _NETDRV_FILE_BOTH_DIR_INFO {
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    ULONG         EaSize;
    CCHAR         ShortNameLength;
    WCHAR         ShortName[12];
    WCHAR         FileName[1];
} NETDRV_FILE_BOTH_DIR_INFO, *PNETDRV_FILE_BOTH_DIR_INFO;

NTSYSAPI NTSTATUS NTAPI ZwQueryDirectoryFile(
    _In_     HANDLE                 FileHandle,
    _In_opt_ HANDLE                 Event,
    _In_opt_ PIO_APC_ROUTINE        ApcRoutine,
    _In_opt_ PVOID                  ApcContext,
    _Out_    PIO_STATUS_BLOCK       IoStatusBlock,
    _Out_    PVOID                  FileInformation,
    _In_     ULONG                  Length,
    _In_     FILE_INFORMATION_CLASS FileInformationClass,
    _In_     BOOLEAN                ReturnSingleEntry,
    _In_opt_ PUNICODE_STRING        FileName,
    _In_     BOOLEAN                RestartScan);

static VOID
Utf8ToHexLineA(_In_reads_(SrcLen) const UCHAR* Src,
               _In_ SIZE_T SrcLen,
               _Out_writes_z_(DstCap) PCHAR Dst,
               _In_ SIZE_T DstCap)
{
    static const CHAR kHex[] = "0123456789ABCDEF";
    SIZE_T j = 0;
    if (DstCap == 0) return;
    for (SIZE_T i = 0; i < SrcLen && j + 2 < DstCap; ++i) {
        Dst[j++] = kHex[(Src[i] >> 4) & 0xF];
        Dst[j++] = kHex[Src[i] & 0xF];
    }
    Dst[j] = 0;
}

NTSTATUS NetDrvEnumFile(_In_z_ PCSTR Utf8Path)
{
    NTSTATUS        status;
    HANDLE          hDir = NULL;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK iosb;
    UNICODE_STRING  ntPath;
    WCHAR           ntPathBuf[600];
    UCHAR*          dirBuf = NULL;
    ARK_UDP_CHANNEL ch;
    BOOLEAN         chOpen = FALSE;
    ULONG           bytesWritten = 0;
    ULONG           utf16Chars;
    SIZE_T          pathLen;
    ULONG           total = 0;
    CHAR            pathHex[600];

    PAGED_CODE();

    pathLen = strlen(Utf8Path);
    while (pathLen > 0 &&
           (Utf8Path[pathLen - 1] == '\r' || Utf8Path[pathLen - 1] == '\n')) {
        --pathLen;
    }
    if (pathLen == 0 || pathLen > 500) {
        LOG("EnumFile: invalid path len=%Iu", pathLen);
        return STATUS_INVALID_PARAMETER;
    }

    // Build NT path "\??\<Win32 path>".
    static const WCHAR kPrefix[] = L"\\??\\";
    RtlCopyMemory(ntPathBuf, kPrefix, sizeof(kPrefix) - sizeof(WCHAR));
    status = RtlUTF8ToUnicodeN(
        ntPathBuf + 4,
        sizeof(ntPathBuf) - 5 * sizeof(WCHAR),
        &bytesWritten,
        Utf8Path,
        (ULONG)pathLen);
    if (!NT_SUCCESS(status)) {
        LOG("EnumFile: RtlUTF8ToUnicodeN failed 0x%08X", status);
        return status;
    }
    utf16Chars = 4 + bytesWritten / sizeof(WCHAR);
    // Strip trailing backslash unless this is a drive root "\??\C:\".
    while (utf16Chars > 7 && ntPathBuf[utf16Chars - 1] == L'\\') {
        --utf16Chars;
    }
    ntPathBuf[utf16Chars] = 0;
    ntPath.Buffer        = ntPathBuf;
    ntPath.Length        = (USHORT)(utf16Chars * sizeof(WCHAR));
    ntPath.MaximumLength = (USHORT)(ntPath.Length + sizeof(WCHAR));

    InitializeObjectAttributes(&oa, &ntPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(&hDir,
        FILE_LIST_DIRECTORY | SYNCHRONIZE | FILE_TRAVERSE,
        &oa, &iosb, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    if (!NT_SUCCESS(status)) {
        LOG("EnumFile: ZwCreateFile %wZ failed 0x%08X", &ntPath, status);
        return status;
    }

    Utf8ToHexLineA((const UCHAR*)Utf8Path, pathLen, pathHex, sizeof(pathHex));

    status = ArkUdpOpen(&ch);
    if (!NT_SUCCESS(status)) {
        ZwClose(hDir);
        return status;
    }
    chOpen = TRUE;

    {
        CHAR startLine[700];
        RtlStringCbPrintfA(startLine, sizeof(startLine), "B|file|%s\n", pathHex);
        ArkUdpSendLine(&ch, startLine);
    }

    dirBuf = (UCHAR*)ExAllocatePool2(POOL_FLAG_PAGED, 0x4000, TAG_ARK);
    if (!dirBuf) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    for (;;) {
        NTSTATUS qstatus = ZwQueryDirectoryFile(hDir, NULL, NULL, NULL, &iosb,
            dirBuf, 0x4000, FileBothDirectoryInformation,
            FALSE, NULL, FALSE);
        if (qstatus == STATUS_NO_MORE_FILES) {
            break;
        }
        if (!NT_SUCCESS(qstatus)) {
            LOG("EnumFile: ZwQueryDirectoryFile failed 0x%08X", qstatus);
            status = qstatus;
            break;
        }

        PNETDRV_FILE_BOTH_DIR_INFO info = (PNETDRV_FILE_BOTH_DIR_INFO)dirBuf;
        for (;;) {
            BOOLEAN isDir = (info->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? TRUE : FALSE;
            ULONG   nameWChars = info->FileNameLength / sizeof(WCHAR);
            BOOLEAN isDot = (nameWChars == 1 && info->FileName[0] == L'.');
            BOOLEAN isDotDot = (nameWChars == 2 &&
                                info->FileName[0] == L'.' &&
                                info->FileName[1] == L'.');

            if (nameWChars > 0 && !isDot && !isDotDot) {
                UCHAR  utf8Name[1024];
                ULONG  utf8Bytes = 0;
                NTSTATUS cvt = RtlUnicodeToUTF8N(
                    (PCHAR)utf8Name, sizeof(utf8Name),
                    &utf8Bytes,
                    info->FileName, info->FileNameLength);
                if (NT_SUCCESS(cvt)) {
                    CHAR nameHex[2100];
                    CHAR line[2200];
                    ULONGLONG sz = isDir
                        ? 0ULL
                        : (ULONGLONG)info->EndOfFile.QuadPart;
                    Utf8ToHexLineA(utf8Name, utf8Bytes, nameHex, sizeof(nameHex));
                    RtlStringCbPrintfA(line, sizeof(line),
                        "F|%u|%llX|%s\n",
                        isDir ? 1u : 0u,
                        sz,
                        nameHex);
                    ArkUdpSendLine(&ch, line);
                    ++total;
                }
            }

            if (info->NextEntryOffset == 0) break;
            info = (PNETDRV_FILE_BOTH_DIR_INFO)((PUCHAR)info + info->NextEntryOffset);
        }
    }

done:
    if (dirBuf) ExFreePoolWithTag(dirBuf, TAG_ARK);
    {
        CHAR endLine[700];
        RtlStringCbPrintfA(endLine, sizeof(endLine),
            "E|file|%s|%u\n", pathHex, total);
        ArkUdpSendLine(&ch, endLine);
    }
    if (chOpen) ArkUdpClose(&ch);
    ZwClose(hDir);
    LOG("EnumFile: '%s' entries=%u final=0x%08X", Utf8Path, total, status);
    return status;
}

// ---------------------------------------------------------------------------
// File download / upload over UDP. Same protocol family as the enum lines:
//   B|get|<pathHex>|<sizeHex>|<chunkSize>|<chunkCount>\n
//   G|<idx>|<offHex>|<lenHex>|<dataHex>\n
//   E|get|<pathHex>|<totalSent>\n
// Upload (app -> driver) uses:
//   C|put|<utf8Path>|<sizeHex>|<chunkSize>|<chunkCount>\n  (NetDrvPutBegin)
//   P|<idx>|<offHex>|<lenHex>|<dataHex>\n                 (NetDrvPutChunk)
//   C|putend|<utf8Path>|<sizeHex>\n                       (NetDrvPutEnd)
// Only one upload may be active at a time. The worker thread serializes
// commands so no extra locking is required for the global put state.
// ---------------------------------------------------------------------------

// Download/upload binary chunk size in source bytes (hex-encoded on the wire,
// so each UDP packet is roughly 2 x this + ~32 bytes of framing).
#define NETDRV_IO_CHUNK_BYTES     512
// TCP can handle much larger chunks -- no UDP MTU limit, no hex overhead concern.
#define NETDRV_IO_CHUNK_BYTES_TCP 32768

NTSYSAPI NTSTATUS NTAPI ZwReadFile(
    _In_     HANDLE              FileHandle,
    _In_opt_ HANDLE              Event,
    _In_opt_ PIO_APC_ROUTINE     ApcRoutine,
    _In_opt_ PVOID               ApcContext,
    _Out_    PIO_STATUS_BLOCK    IoStatusBlock,
    _Out_    PVOID               Buffer,
    _In_     ULONG               Length,
    _In_opt_ PLARGE_INTEGER      ByteOffset,
    _In_opt_ PULONG              Key);

NTSYSAPI NTSTATUS NTAPI ZwWriteFile(
    _In_     HANDLE              FileHandle,
    _In_opt_ HANDLE              Event,
    _In_opt_ PIO_APC_ROUTINE     ApcRoutine,
    _In_opt_ PVOID               ApcContext,
    _Out_    PIO_STATUS_BLOCK    IoStatusBlock,
    _In_     PVOID               Buffer,
    _In_     ULONG               Length,
    _In_opt_ PLARGE_INTEGER      ByteOffset,
    _In_opt_ PULONG              Key);

typedef struct _NETDRV_FILE_STANDARD_INFO {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} NETDRV_FILE_STANDARD_INFO;

NTSYSAPI NTSTATUS NTAPI ZwQueryInformationFile(
    _In_     HANDLE                  FileHandle,
    _Out_    PIO_STATUS_BLOCK        IoStatusBlock,
    _Out_    PVOID                   FileInformation,
    _In_     ULONG                   Length,
    _In_     FILE_INFORMATION_CLASS  FileInformationClass);

// --- hex decode (paired with Utf8ToHexLineA above) -------------------------
static int NetDrvHexNibble(CHAR c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static NTSTATUS NetDrvHexDecodeA(_In_reads_(srcLen) PCSTR src, _In_ SIZE_T srcLen,
                                 _Out_writes_(dstCap) PUCHAR dst, _In_ SIZE_T dstCap,
                                 _Out_ PSIZE_T outBytes)
{
    SIZE_T bytes = srcLen / 2;
    if (srcLen & 1) return STATUS_INVALID_PARAMETER;
    if (bytes > dstCap) return STATUS_BUFFER_OVERFLOW;
    for (SIZE_T i = 0; i < bytes; ++i) {
        int hi = NetDrvHexNibble(src[i * 2]);
        int lo = NetDrvHexNibble(src[i * 2 + 1]);
        if (hi < 0 || lo < 0) return STATUS_INVALID_PARAMETER;
        dst[i] = (UCHAR)((hi << 4) | lo);
    }
    *outBytes = bytes;
    return STATUS_SUCCESS;
}

// --- open helper: utf8 -> "\??\..." -> ZwCreateFile ------------------------
//
// On STATUS_SHARING_VIOLATION we retry via IoCreateFileEx with
// IO_IGNORE_SHARE_ACCESS_CHECK so the driver can read files that are held by
// another process with exclusive access (logs, in-use exe/dll, etc.).
// NOTE: kernel-owned files like swapfile.sys / pagefile.sys are also blocked
// by Mm section locks; this bypass opens the handle but ZwReadFile may still
// return errors on them. That is expected.

#ifndef IO_IGNORE_SHARE_ACCESS_CHECK
#define IO_IGNORE_SHARE_ACCESS_CHECK 0x00000010
#endif

static NTSTATUS NetDrvOpenWin32File(_In_z_ PCSTR Utf8Path,
                                    _In_ ACCESS_MASK Access,
                                    _In_ ULONG Disposition,
                                    _In_ ULONG ShareAccess,
                                    _In_ ULONG CreateOptions,
                                    _Out_ HANDLE* OutHandle)
{
    WCHAR  buf[600];
    UNICODE_STRING ntPath;
    OBJECT_ATTRIBUTES oa;
    IO_STATUS_BLOCK   iosb;
    ULONG  bytesWritten = 0;
    ULONG  chars;
    NTSTATUS status;
    SIZE_T pathLen;

    *OutHandle = NULL;
    pathLen = strlen(Utf8Path);
    while (pathLen > 0 &&
           (Utf8Path[pathLen - 1] == '\r' || Utf8Path[pathLen - 1] == '\n')) {
        --pathLen;
    }
    if (pathLen == 0 || pathLen > 500) return STATUS_INVALID_PARAMETER;

    static const WCHAR kPrefix[] = L"\\??\\";
    RtlCopyMemory(buf, kPrefix, sizeof(kPrefix) - sizeof(WCHAR));
    status = RtlUTF8ToUnicodeN(buf + 4,
                               sizeof(buf) - 5 * sizeof(WCHAR),
                               &bytesWritten, Utf8Path, (ULONG)pathLen);
    if (!NT_SUCCESS(status)) return status;
    chars = 4 + bytesWritten / sizeof(WCHAR);
    buf[chars] = 0;
    ntPath.Buffer        = buf;
    ntPath.Length        = (USHORT)(chars * sizeof(WCHAR));
    ntPath.MaximumLength = (USHORT)(ntPath.Length + sizeof(WCHAR));

    InitializeObjectAttributes(&oa, &ntPath,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateFile(OutHandle, Access, &oa, &iosb, NULL,
                          FILE_ATTRIBUTE_NORMAL, ShareAccess, Disposition,
                          CreateOptions, NULL, 0);

    if (status == STATUS_SHARING_VIOLATION) {
        // Retry: ask the IO manager to skip the share-access check.
        LOG("OpenWin32File: share violation, retrying with IO_IGNORE_SHARE_ACCESS_CHECK");
        status = IoCreateFileEx(OutHandle, Access, &oa, &iosb,
                                NULL, FILE_ATTRIBUTE_NORMAL,
                                ShareAccess, Disposition, CreateOptions,
                                NULL, 0,
                                CreateFileTypeNone, NULL,
                                IO_IGNORE_SHARE_ACCESS_CHECK,
                                NULL);
        LOG("OpenWin32File: bypass open status=0x%08X", status);
    }
    return status;
}

// --- short status helper ---------------------------------------------------
static VOID NetDrvAppSendLine(_In_z_ PCSTR text)
{
    ARK_UDP_CHANNEL ch;
    if (NT_SUCCESS(ArkUdpOpen(&ch))) {
        ArkUdpSendLine(&ch, text);
        ArkUdpClose(&ch);
    }
}

NTSTATUS NetDrvGetFile(_In_z_ PCSTR Utf8Path)
{
    NTSTATUS        status;
    HANDLE          hFile = NULL;
    IO_STATUS_BLOCK iosb;
    NETDRV_FILE_STANDARD_INFO fsi = { 0 };
    UCHAR*          buf = NULL;
    UCHAR*          hexBuf = NULL;
    PCHAR           lineBuf = NULL;
    CHAR            line[1400];
    CHAR            pathHex[600];
    ARK_UDP_CHANNEL ch;
    BOOLEAN         chOpen = FALSE;
    SIZE_T          pathLen;
    ULONGLONG       total;
    ULONGLONG       sentBytes = 0;
    ULONG           chunkIdx = 0;

    PAGED_CODE();

    pathLen = strlen(Utf8Path);
    while (pathLen > 0 &&
           (Utf8Path[pathLen - 1] == '\r' || Utf8Path[pathLen - 1] == '\n')) {
        --pathLen;
    }

    status = NetDrvOpenWin32File(Utf8Path,
        FILE_READ_DATA | SYNCHRONIZE,
        FILE_OPEN,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        &hFile);
    if (!NT_SUCCESS(status)) {
        RtlStringCbPrintfA(line, sizeof(line),
            "S|get-error|0x%08X|%s\n", status, Utf8Path);
        NetDrvAppSendLine(line);
        LOG("GetFile: open failed 0x%08X path='%s'", status, Utf8Path);
        return status;
    }

    status = ZwQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi),
                                    FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        ZwClose(hFile);
        RtlStringCbPrintfA(line, sizeof(line),
            "S|get-error|query|0x%08X|%s\n", status, Utf8Path);
        NetDrvAppSendLine(line);
        return status;
    }
    total = (ULONGLONG)fsi.EndOfFile.QuadPart;

    Utf8ToHexLineA((const UCHAR*)Utf8Path, pathLen, pathHex, sizeof(pathHex));

    if (!NT_SUCCESS(ArkUdpOpen(&ch))) {
        ZwClose(hFile);
        return STATUS_NETWORK_UNREACHABLE;
    }
    chOpen = TRUE;

    /* Pick chunk size: 32KB for TCP, 512B for UDP */
    BOOLEAN useTcp = TcpLinkIsFileConnected();
    ULONG ioChunk = useTcp ? NETDRV_IO_CHUNK_BYTES_TCP : NETDRV_IO_CHUNK_BYTES;

    {
        ULONGLONG chunkCount = (total + ioChunk - 1) / ioChunk;
        if (chunkCount == 0) chunkCount = 1;
        RtlStringCbPrintfA(line, sizeof(line),
            "B|get|%s|%llX|%u|%llu\n",
            pathHex, total, ioChunk, chunkCount);
        ArkUdpSendLine(&ch, line);
    }

    buf    = (UCHAR*)ExAllocatePool2(POOL_FLAG_PAGED, ioChunk, TAG_ARK);
    hexBuf = (UCHAR*)ExAllocatePool2(POOL_FLAG_PAGED, ioChunk * 2 + 2, TAG_ARK);
    /* lineBuf must hold "G|idx|offHex|lenHex|" + hex data + "\n\0" */
    lineBuf = (PCHAR)ExAllocatePool2(POOL_FLAG_PAGED, ioChunk * 2 + 128, TAG_ARK);
    if (!buf || !hexBuf || !lineBuf) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    {
        LARGE_INTEGER off;
        off.QuadPart = 0;
        for (;;) {
            NTSTATUS rs = ZwReadFile(hFile, NULL, NULL, NULL, &iosb,
                buf, ioChunk, &off, NULL);
            if (rs == STATUS_END_OF_FILE || iosb.Information == 0) {
                break;
            }
            if (!NT_SUCCESS(rs)) {
                status = rs;
                LOG("GetFile: read failed 0x%08X off=%lld", rs, off.QuadPart);
                break;
            }
            ULONG bytes = (ULONG)iosb.Information;
            Utf8ToHexLineA(buf, bytes, (PCHAR)hexBuf, ioChunk * 2 + 2);
            RtlStringCbPrintfA(lineBuf, ioChunk * 2 + 128,
                "G|%u|%llX|%X|%s\n", chunkIdx, (ULONGLONG)off.QuadPart, bytes, hexBuf);
            ArkUdpSendLine(&ch, lineBuf);
            ++chunkIdx;
            sentBytes += bytes;
            off.QuadPart += bytes;
            if (bytes < ioChunk) break;
            /* Pacing: only throttle for UDP (small chunks flood the receiver) */
            if (!useTcp && (chunkIdx & 3) == 3) {
                LARGE_INTEGER sleep;
                sleep.QuadPart = -20000; // 2 ms
                KeDelayExecutionThread(KernelMode, FALSE, &sleep);
            }
        }
    }

done:
    if (buf)     ExFreePoolWithTag(buf,     TAG_ARK);
    if (hexBuf)  ExFreePoolWithTag(hexBuf,  TAG_ARK);
    if (lineBuf) ExFreePoolWithTag(lineBuf, TAG_ARK);

    RtlStringCbPrintfA(line, sizeof(line),
        "E|get|%s|%llu\n", pathHex, sentBytes);
    ArkUdpSendLine(&ch, line);

    if (chOpen) ArkUdpClose(&ch);
    ZwClose(hFile);
    LOG("GetFile: '%s' size=%llu sent=%llu chunks=%u status=0x%08X",
        Utf8Path, total, sentBytes, chunkIdx, status);
    return status;
}

// --- upload state (single-writer; worker thread serializes access) --------
static BOOLEAN    g_PutActive       = FALSE;
static HANDLE     g_PutHandle       = NULL;
static CHAR       g_PutPath[520]    = { 0 };
static SIZE_T     g_PutPathLen      = 0;
static ULONGLONG  g_PutTotalBytes   = 0;
static ULONGLONG  g_PutWritten      = 0;
static ULONG      g_PutChunkCount   = 0;
static ULONG      g_PutChunksDone   = 0;

static VOID NetDrvPutResetState(VOID)
{
    if (g_PutHandle) {
        ZwClose(g_PutHandle);
        g_PutHandle = NULL;
    }
    g_PutActive       = FALSE;
    g_PutPathLen      = 0;
    g_PutTotalBytes   = 0;
    g_PutWritten      = 0;
    g_PutChunkCount   = 0;
    g_PutChunksDone   = 0;
    g_PutPath[0]      = 0;
}

NTSTATUS NetDrvPutBegin(_In_z_ PCSTR HeaderRest)
{
    // HeaderRest: <utf8Path>|<sizeHex>|<chunkSize>|<chunkCount>\n
    PCSTR sizeStart, chunkStart, countStart;
    PCSTR pathEnd;
    CHAR   line[256];
    NTSTATUS status;

    PAGED_CODE();

    if (g_PutActive) {
        NetDrvAppSendLine("S|put-error|busy\n");
        return STATUS_DEVICE_BUSY;
    }
    NetDrvPutResetState();

    pathEnd = strchr(HeaderRest, '|');
    if (!pathEnd) return STATUS_INVALID_PARAMETER;
    sizeStart = pathEnd + 1;
    chunkStart = strchr(sizeStart, '|');
    if (!chunkStart) return STATUS_INVALID_PARAMETER;
    ++chunkStart;
    countStart = strchr(chunkStart, '|');
    if (!countStart) return STATUS_INVALID_PARAMETER;
    ++countStart;

    SIZE_T pathLen = (SIZE_T)(pathEnd - HeaderRest);
    if (pathLen == 0 || pathLen >= sizeof(g_PutPath)) return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(g_PutPath, HeaderRest, pathLen);
    g_PutPath[pathLen] = 0;
    g_PutPathLen = pathLen;

    g_PutTotalBytes = _strtoui64(sizeStart, NULL, 16);
    {
        ULONG cc = 0;
        (void)RtlCharToInteger(countStart, 10, &cc);
        g_PutChunkCount = cc;
    }

    status = NetDrvOpenWin32File(g_PutPath,
        FILE_WRITE_DATA | SYNCHRONIZE,
        FILE_OVERWRITE_IF,
        FILE_SHARE_READ,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        &g_PutHandle);
    if (!NT_SUCCESS(status)) {
        RtlStringCbPrintfA(line, sizeof(line),
            "S|put-open-error|0x%08X|%s\n", status, g_PutPath);
        NetDrvAppSendLine(line);
        NetDrvPutResetState();
        return status;
    }

    g_PutActive = TRUE;
    RtlStringCbPrintfA(line, sizeof(line),
        "S|put-open|%llX|%u\n", g_PutTotalBytes, g_PutChunkCount);
    NetDrvAppSendLine(line);
    LOG("PutBegin: '%s' total=%llu chunks=%u", g_PutPath,
        g_PutTotalBytes, g_PutChunkCount);
    return STATUS_SUCCESS;
}

NTSTATUS NetDrvPutChunk(_In_z_ PCSTR ChunkRest)
{
    // ChunkRest: <idx>|<offHex>|<lenHex>|<dataHex>\n
    PCSTR p, offStart, lenStart, dataStart;
    ULONG     idx;
    ULONGLONG offset;
    ULONG     dataLen;
    SIZE_T    hexLen;
    PUCHAR    tmp = NULL;
    SIZE_T    decoded = 0;
    IO_STATUS_BLOCK iosb;
    LARGE_INTEGER off;
    NTSTATUS  status;

    PAGED_CODE();

    if (!g_PutActive || !g_PutHandle) return STATUS_INVALID_DEVICE_STATE;

    p = ChunkRest;
    offStart = strchr(p, '|'); if (!offStart) return STATUS_INVALID_PARAMETER; ++offStart;
    lenStart = strchr(offStart, '|'); if (!lenStart) return STATUS_INVALID_PARAMETER; ++lenStart;
    dataStart = strchr(lenStart, '|'); if (!dataStart) return STATUS_INVALID_PARAMETER; ++dataStart;

    {
        ULONG ii = 0, ll = 0;
        (void)RtlCharToInteger(p, 10, &ii);
        idx     = ii;
        offset  = _strtoui64(offStart, NULL, 16);
        (void)RtlCharToInteger(lenStart, 16, &ll);
        dataLen = ll;
    }

    // dataStart .. end of cmd (trim trailing \r\n).
    hexLen = strlen(dataStart);
    while (hexLen > 0 &&
           (dataStart[hexLen - 1] == '\r' || dataStart[hexLen - 1] == '\n')) {
        --hexLen;
    }
    if (hexLen != (SIZE_T)dataLen * 2 || dataLen > NETDRV_IO_CHUNK_BYTES_TCP) {
        LOG("PutChunk: bad sizes hex=%Iu len=%u", hexLen, dataLen);
        return STATUS_INVALID_PARAMETER;
    }
    tmp = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, dataLen, TAG_ARK);
    if (!tmp) return STATUS_INSUFFICIENT_RESOURCES;
    status = NetDrvHexDecodeA(dataStart, hexLen, tmp, dataLen, &decoded);
    if (!NT_SUCCESS(status) || decoded != dataLen) {
        LOG("PutChunk: hex decode failed 0x%08X", status);
        ExFreePoolWithTag(tmp, TAG_ARK);
        return STATUS_INVALID_PARAMETER;
    }

    off.QuadPart = (LONGLONG)offset;
    status = ZwWriteFile(g_PutHandle, NULL, NULL, NULL, &iosb,
                         tmp, dataLen, &off, NULL);
    ExFreePoolWithTag(tmp, TAG_ARK);
    if (!NT_SUCCESS(status)) {
        CHAR line[160];
        RtlStringCbPrintfA(line, sizeof(line),
            "S|put-chunk-err|%u|0x%08X\n", idx, status);
        NetDrvAppSendLine(line);
        LOG("PutChunk: write idx=%u off=%llu failed 0x%08X", idx, offset, status);
        return status;
    }
    g_PutWritten += (ULONG)iosb.Information;
    ++g_PutChunksDone;
    return STATUS_SUCCESS;
}

NTSTATUS NetDrvPutEnd(_In_z_ PCSTR EndRest)
{
    // EndRest: <utf8Path>|<sizeHex>\n
    CHAR line[256];
    ULONGLONG expected;
    PCSTR sizeStart;

    PAGED_CODE();

    if (!g_PutActive) {
        NetDrvAppSendLine("S|put-end|not-active\n");
        return STATUS_INVALID_DEVICE_STATE;
    }

    sizeStart = strchr(EndRest, '|');
    expected = (sizeStart) ? _strtoui64(sizeStart + 1, NULL, 16) : g_PutTotalBytes;

    RtlStringCbPrintfA(line, sizeof(line),
        "S|put-done|recv=%llu|expect=%llu|chunks=%u/%u\n",
        g_PutWritten, expected, g_PutChunksDone, g_PutChunkCount);
    NetDrvAppSendLine(line);
    LOG("PutEnd: written=%llu expect=%llu chunks=%u/%u",
        g_PutWritten, expected, g_PutChunksDone, g_PutChunkCount);

    NetDrvPutResetState();
    return STATUS_SUCCESS;
}
