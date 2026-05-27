/*++

Module Name:

    Wsk.c

Abstract:

    Minimal Winsock Kernel (WSK) wrapper. Provides synchronous TCP/UDP
    send/recv on top of WSK provider NPI. Style modeled after libwsk:

        - one global WSK_REGISTRATION + WSK_PROVIDER_NPI
        - every async op uses a private IRP with an IoCompletion routine
          that signals a KEVENT, and the wrapper waits on the event.

--*/

#include "Wsk.h"

#define WSK_POOL_TAG  'kswW'

//
// Globals
//
static WSK_REGISTRATION  g_WskRegistration;
static WSK_PROVIDER_NPI  g_WskProvider;
static WSK_CLIENT_DISPATCH g_WskClientDispatch = {
    MAKE_WSK_VERSION(1, 0),
    0,
    NULL                 // No extension callbacks
};
static BOOLEAN g_WskRegistered = FALSE;
static BOOLEAN g_WskProviderCaptured = FALSE;

//
// Per-call sync context: IRP completion signals Event; caller reads Status.
//
typedef struct _WSK_SYNC_CTX {
    KEVENT     Event;
} WSK_SYNC_CTX, *PWSK_SYNC_CTX;

static
IO_COMPLETION_ROUTINE WskSyncCompletion;

static NTSTATUS
WskSyncCompletion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP           Irp,
    _In_ PVOID          Context
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    PWSK_SYNC_CTX ctx = (PWSK_SYNC_CTX)Context;
    KeSetEvent(&ctx->Event, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

//
// Allocate an IRP for a single WSK call and prime it with our completion.
//
static PIRP
WskAllocIrp(_Out_ PWSK_SYNC_CTX Ctx)
{
    PIRP irp = IoAllocateIrp(1, FALSE);
    if (irp == NULL) {
        return NULL;
    }
    KeInitializeEvent(&Ctx->Event, NotificationEvent, FALSE);
    irp->IoStatus.Status = STATUS_PENDING;
    irp->IoStatus.Information = 0;
    IoSetCompletionRoutine(irp, WskSyncCompletion, Ctx, TRUE, TRUE, TRUE);
    return irp;
}

//
// Wait for an already-issued WSK IRP to complete; return final NTSTATUS
// and (optionally) Information.
//
static NTSTATUS
WskWaitIrp(_In_ PIRP Irp,
           _In_ PWSK_SYNC_CTX Ctx,
           _In_ NTSTATUS InitialStatus,
           _Out_opt_ SIZE_T* Information)
{
    NTSTATUS status = InitialStatus;
    if (InitialStatus == STATUS_PENDING) {
        KeWaitForSingleObject(&Ctx->Event, Executive, KernelMode, FALSE, NULL);
        status = Irp->IoStatus.Status;
    }
    if (Information) {
        *Information = Irp->IoStatus.Information;
    }
    IoFreeIrp(Irp);
    return status;
}

// ---------------------------------------------------------------------------
// Startup / Cleanup
// ---------------------------------------------------------------------------

NTSTATUS
WSKStartup(_In_ USHORT Version)
{
    NTSTATUS status;
    WSK_CLIENT_NPI clientNpi;

    if (g_WskRegistered) {
        return STATUS_SUCCESS;
    }

    g_WskClientDispatch.Version = Version;

    clientNpi.ClientContext = NULL;
    clientNpi.Dispatch      = &g_WskClientDispatch;

    status = WskRegister(&clientNpi, &g_WskRegistration);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    g_WskRegistered = TRUE;

    status = WskCaptureProviderNPI(&g_WskRegistration,
                                   WSK_INFINITE_WAIT,
                                   &g_WskProvider);
    if (!NT_SUCCESS(status)) {
        WskDeregister(&g_WskRegistration);
        g_WskRegistered = FALSE;
        return status;
    }
    g_WskProviderCaptured = TRUE;
    return STATUS_SUCCESS;
}

VOID
WSKCleanup(VOID)
{
    if (g_WskProviderCaptured) {
        WskReleaseProviderNPI(&g_WskRegistration);
        g_WskProviderCaptured = FALSE;
    }
    if (g_WskRegistered) {
        WskDeregister(&g_WskRegistration);
        g_WskRegistered = FALSE;
    }
}

// ---------------------------------------------------------------------------
// Socket lifecycle
// ---------------------------------------------------------------------------

NTSTATUS
WSK_socket(
    _Out_ PWSK_SOCKET* Socket,
    _In_  ADDRESS_FAMILY AddressFamily,
    _In_  USHORT         SocketType,
    _In_  ULONG          Protocol,
    _In_  ULONG          Flags
)
{
    return WSK_socket_ex(Socket, AddressFamily, SocketType, Protocol,
                         Flags, NULL, NULL);
}

NTSTATUS
WSK_socket_ex(
    _Out_ PWSK_SOCKET* Socket,
    _In_  ADDRESS_FAMILY AddressFamily,
    _In_  USHORT         SocketType,
    _In_  ULONG          Protocol,
    _In_  ULONG          Flags,
    _In_opt_ PVOID       SocketContext,
    _In_opt_ CONST VOID* Dispatch
)
{
    WSK_SYNC_CTX ctx;
    PIRP irp;
    NTSTATUS status;
    SIZE_T info = 0;

    *Socket = NULL;
    if (!g_WskProviderCaptured) {
        return STATUS_DEVICE_NOT_READY;
    }

    irp = WskAllocIrp(&ctx);
    if (!irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = g_WskProvider.Dispatch->WskSocket(
        g_WskProvider.Client,
        AddressFamily,
        SocketType,
        Protocol,
        Flags,
        SocketContext,
        Dispatch,
        NULL,    // OwningProcess
        NULL,    // OwningThread
        NULL,    // SecurityDescriptor
        irp);

    status = WskWaitIrp(irp, &ctx, status, &info);
    if (NT_SUCCESS(status)) {
        *Socket = (PWSK_SOCKET)info;
    }
    return status;
}

NTSTATUS
WSKControlSocket(
    _In_ PWSK_SOCKET Socket,
    _In_ WSK_CONTROL_SOCKET_TYPE RequestType,
    _In_ ULONG ControlCode,
    _In_ ULONG Level,
    _In_ SIZE_T InputSize,
    _In_reads_bytes_opt_(InputSize) PVOID InputBuffer,
    _In_ SIZE_T OutputSize,
    _Out_writes_bytes_opt_(OutputSize) PVOID OutputBuffer,
    _Out_opt_ SIZE_T* OutputSizeReturned
)
{
    WSK_SYNC_CTX ctx;
    PIRP irp;
    NTSTATUS status;
    SIZE_T info = 0;
    PWSK_PROVIDER_BASIC_DISPATCH d;

    if (!Socket) return STATUS_INVALID_PARAMETER;

    irp = WskAllocIrp(&ctx);
    if (!irp) return STATUS_INSUFFICIENT_RESOURCES;

    d = (PWSK_PROVIDER_BASIC_DISPATCH)Socket->Dispatch;
    status = d->WskControlSocket(Socket,
                                 RequestType,
                                 ControlCode,
                                 Level,
                                 InputSize,
                                 InputBuffer,
                                 OutputSize,
                                 OutputBuffer,
                                 OutputSizeReturned,
                                 irp);
    status = WskWaitIrp(irp, &ctx, status, &info);
    if (OutputSizeReturned) {
        *OutputSizeReturned = info;
    }
    return status;
}

NTSTATUS
WSK_closesocket(_In_ PWSK_SOCKET Socket)
{
    WSK_SYNC_CTX ctx;
    PIRP irp;
    NTSTATUS status;
    PWSK_PROVIDER_BASIC_DISPATCH d;

    if (!Socket) return STATUS_INVALID_PARAMETER;

    irp = WskAllocIrp(&ctx);
    if (!irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    d = (PWSK_PROVIDER_BASIC_DISPATCH)Socket->Dispatch;
    status = d->WskCloseSocket(Socket, irp);
    return WskWaitIrp(irp, &ctx, status, NULL);
}

// ---------------------------------------------------------------------------
// Bind / Connect
// ---------------------------------------------------------------------------

NTSTATUS
WSKBind(_In_ PWSK_SOCKET Socket, _In_ PSOCKADDR LocalAddress)
{
    WSK_SYNC_CTX ctx;
    PIRP irp;
    NTSTATUS status;

    if (!Socket || !LocalAddress) return STATUS_INVALID_PARAMETER;

    irp = WskAllocIrp(&ctx);
    if (!irp) return STATUS_INSUFFICIENT_RESOURCES;

    // Bind dispatch differs per socket category, but all categories that
    // support bind expose it at the same slot of their dispatch table
    // (WskBind is the 1st routine after the basic-dispatch header for
    //  listening/connection/datagram sockets). We use the connection
    //  dispatch view as a convenient typed alias.
    PWSK_PROVIDER_CONNECTION_DISPATCH d =
        (PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch;
    status = d->WskBind(Socket, LocalAddress, 0, irp);
    return WskWaitIrp(irp, &ctx, status, NULL);
}

NTSTATUS
WSKConnect(_In_ PWSK_SOCKET Socket, _In_ PSOCKADDR RemoteAddress)
{
    NTSTATUS status;
    SOCKADDR_IN6 anyAddr = { 0 };
    PSOCKADDR localAny;

    if (!Socket || !RemoteAddress) return STATUS_INVALID_PARAMETER;

    // Bind to wildcard local address first (required before connect).
    if (RemoteAddress->sa_family == AF_INET) {
        SOCKADDR_IN any4 = { 0 };
        any4.sin_family = AF_INET;
        RtlCopyMemory(&anyAddr, &any4, sizeof(any4));
    } else {
        anyAddr.sin6_family = AF_INET6;
    }
    localAny = (PSOCKADDR)&anyAddr;

    status = WSKBind(Socket, localAny);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WSK_SYNC_CTX ctx;
    PIRP irp = WskAllocIrp(&ctx);
    if (!irp) return STATUS_INSUFFICIENT_RESOURCES;

    PWSK_PROVIDER_CONNECTION_DISPATCH d =
        (PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch;
    status = d->WskConnect(Socket, RemoteAddress, 0, irp);
    return WskWaitIrp(irp, &ctx, status, NULL);
}

// ---------------------------------------------------------------------------
// TCP send / recv
// ---------------------------------------------------------------------------

//
// Build a single-element WSK_BUF that locks `Buffer` for the operation.
// Returns NULL on failure; caller frees with WskFreeBuf().
//
static PMDL
WskBuildBuf(_In_ PVOID Buffer, _In_ SIZE_T Length, _Out_ WSK_BUF* Wb)
{
    PMDL mdl = IoAllocateMdl(Buffer, (ULONG)Length, FALSE, FALSE, NULL);
    if (!mdl) {
        return NULL;
    }
    __try {
        MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        IoFreeMdl(mdl);
        return NULL;
    }
    Wb->Mdl    = mdl;
    Wb->Offset = 0;
    Wb->Length = Length;
    return mdl;
}

static VOID
WskFreeBuf(_In_ PMDL Mdl)
{
    if (Mdl) {
        MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
    }
}

NTSTATUS
WSKSend(
    _In_  PWSK_SOCKET Socket,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_  SIZE_T Length,
    _Out_ SIZE_T* BytesTransferred,
    _In_  ULONG  Flags
)
{
    WSK_SYNC_CTX ctx;
    WSK_BUF wb;
    PIRP irp;
    PMDL mdl;
    NTSTATUS status;

    *BytesTransferred = 0;
    if (!Socket || !Buffer || Length == 0) return STATUS_INVALID_PARAMETER;

    mdl = WskBuildBuf(Buffer, Length, &wb);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;

    irp = WskAllocIrp(&ctx);
    if (!irp) {
        WskFreeBuf(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PWSK_PROVIDER_CONNECTION_DISPATCH d =
        (PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch;
    status = d->WskSend(Socket, &wb, Flags, irp);
    status = WskWaitIrp(irp, &ctx, status, BytesTransferred);
    WskFreeBuf(mdl);
    return status;
}

NTSTATUS
WSKReceive(
    _In_  PWSK_SOCKET Socket,
    _Out_writes_bytes_to_(Length, *BytesTransferred) PVOID Buffer,
    _In_  SIZE_T Length,
    _Out_ SIZE_T* BytesTransferred,
    _In_  ULONG  Flags
)
{
    WSK_SYNC_CTX ctx;
    WSK_BUF wb;
    PIRP irp;
    PMDL mdl;
    NTSTATUS status;

    *BytesTransferred = 0;
    if (!Socket || !Buffer || Length == 0) return STATUS_INVALID_PARAMETER;

    mdl = WskBuildBuf(Buffer, Length, &wb);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;

    irp = WskAllocIrp(&ctx);
    if (!irp) {
        WskFreeBuf(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PWSK_PROVIDER_CONNECTION_DISPATCH d =
        (PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch;
    status = d->WskReceive(Socket, &wb, Flags, irp);
    status = WskWaitIrp(irp, &ctx, status, BytesTransferred);
    WskFreeBuf(mdl);
    return status;
}

// ---------------------------------------------------------------------------
// UDP sendto / recvfrom
// ---------------------------------------------------------------------------

NTSTATUS
WSKSendTo(
    _In_  PWSK_SOCKET Socket,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_  SIZE_T Length,
    _Out_ SIZE_T* BytesTransferred,
    _In_  PSOCKADDR RemoteAddress
)
{
    WSK_SYNC_CTX ctx;
    WSK_BUF wb;
    PIRP irp;
    PMDL mdl;
    NTSTATUS status;

    *BytesTransferred = 0;
    if (!Socket || !Buffer || Length == 0 || !RemoteAddress)
        return STATUS_INVALID_PARAMETER;

    mdl = WskBuildBuf(Buffer, Length, &wb);
    if (!mdl) return STATUS_INSUFFICIENT_RESOURCES;

    irp = WskAllocIrp(&ctx);
    if (!irp) {
        WskFreeBuf(mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PWSK_PROVIDER_DATAGRAM_DISPATCH d =
        (PWSK_PROVIDER_DATAGRAM_DISPATCH)Socket->Dispatch;
    status = d->WskSendTo(Socket, &wb, 0, RemoteAddress, 0, NULL, irp);
    status = WskWaitIrp(irp, &ctx, status, BytesTransferred);
    WskFreeBuf(mdl);
    return status;
}

