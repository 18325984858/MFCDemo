/*++

Module Name:

    Wsk.h

Abstract:

    Minimal Winsock Kernel (WSK) helper interface.
    Style modeled after libwsk: synchronous wrappers built on top of
    WSK provider NPI using an IoCompletion routine + KEVENT to wait.

--*/

#pragma once

#include <ntddk.h>
#include <wsk.h>

#ifdef __cplusplus
extern "C" {
#endif

//
// One-time global init / teardown of WSK provider NPI.
// Call from DriverEntry / DriverUnload.
//
NTSTATUS
WSKStartup(
    _In_ USHORT Version       // MAKE_WSK_VERSION(1,0)
);

VOID
WSKCleanup(VOID);

//
// Create a socket. SocketType / Protocol / Flags match WskSocket().
// AddressFamily is AF_INET or AF_INET6.
//
NTSTATUS
WSK_socket(
    _Out_ PWSK_SOCKET* Socket,
    _In_  ADDRESS_FAMILY AddressFamily,
    _In_  USHORT         SocketType,    // SOCK_STREAM / SOCK_DGRAM
    _In_  ULONG          Protocol,      // IPPROTO_TCP / IPPROTO_UDP
    _In_  ULONG          Flags          // WSK_FLAG_CONNECTION_SOCKET / WSK_FLAG_DATAGRAM_SOCKET
);

NTSTATUS
WSK_socket_ex(
    _Out_ PWSK_SOCKET* Socket,
    _In_  ADDRESS_FAMILY AddressFamily,
    _In_  USHORT         SocketType,
    _In_  ULONG          Protocol,
    _In_  ULONG          Flags,
    _In_opt_ PVOID       SocketContext,
    _In_opt_ CONST VOID* Dispatch
);

NTSTATUS
WSK_closesocket(
    _In_ PWSK_SOCKET Socket
);

//
// TCP: bind any-local + connect to RemoteAddress.
//
NTSTATUS
WSKConnect(
    _In_ PWSK_SOCKET Socket,
    _In_ PSOCKADDR   RemoteAddress
);

//
// TCP send/recv on a connected socket.
// Returns STATUS_SUCCESS and writes *BytesTransferred on success.
//
NTSTATUS
WSKSend(
    _In_  PWSK_SOCKET Socket,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_  SIZE_T Length,
    _Out_ SIZE_T* BytesTransferred,
    _In_  ULONG  Flags
);

NTSTATUS
WSKReceive(
    _In_  PWSK_SOCKET Socket,
    _Out_writes_bytes_to_(Length, *BytesTransferred) PVOID Buffer,
    _In_  SIZE_T Length,
    _Out_ SIZE_T* BytesTransferred,
    _In_  ULONG  Flags
);

//
// UDP send to a specific peer. Receive-side control packets are handled by
// WskReceiveFromEvent in NetControl.c.
//
NTSTATUS
WSKSendTo(
    _In_  PWSK_SOCKET Socket,
    _In_reads_bytes_(Length) PVOID Buffer,
    _In_  SIZE_T Length,
    _Out_ SIZE_T* BytesTransferred,
    _In_  PSOCKADDR RemoteAddress
);

//
// Bind a (datagram or listening) socket to a local address.
//
NTSTATUS
WSKBind(
    _In_ PWSK_SOCKET Socket,
    _In_ PSOCKADDR   LocalAddress
);

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
);

#ifdef __cplusplus
}
#endif
