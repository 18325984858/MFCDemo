/*++
    TcpChannel.h --- Kernel-mode WSK TCP channel object.
--*/

#pragma once

#include <ntddk.h>
#include <wsk.h>

typedef VOID (*TCP_CHANNEL_DISPATCH)(
    _In_reads_bytes_(Len) const CHAR* Payload,
    _In_ ULONG Len);

typedef struct _TCP_SEND_ITEM {
    LIST_ENTRY Link;
    ULONG      Len;
    UCHAR      Data[1];
} TCP_SEND_ITEM, *PTCP_SEND_ITEM;

typedef struct _TCP_CHANNEL {
    PCSTR                Name;
    USHORT               Port;
    BOOLEAN              SendHello;
    TCP_CHANNEL_DISPATCH Dispatch;

    HANDLE               ConnectThread;
    HANDLE               SendThread;
    volatile LONG        Stop;
    volatile LONG        Connected;
    volatile LONG        Closing;
    volatile LONG        ActiveSends;
    PWSK_SOCKET          Socket;

    KEVENT               StopEvent;
    KEVENT               SendEvent;
    KEVENT               SendIdleEvent;
    FAST_MUTEX           SendMutex;
    FAST_MUTEX           StateMutex;
    LIST_ENTRY           SendListHigh;
    LIST_ENTRY           SendListNorm;
} TCP_CHANNEL, *PTCP_CHANNEL;

VOID
TcpChannelInit(
    _Out_ PTCP_CHANNEL Channel,
    _In_z_ PCSTR Name,
    _In_ USHORT Port,
    _In_opt_ TCP_CHANNEL_DISPATCH Dispatch,
    _In_ BOOLEAN SendHello);

NTSTATUS
TcpChannelStart(_Inout_ PTCP_CHANNEL Channel);

VOID
TcpChannelStop(_Inout_ PTCP_CHANNEL Channel);

NTSTATUS
TcpChannelSend(
    _Inout_ PTCP_CHANNEL Channel,
    _In_reads_bytes_(Len) const VOID* Data,
    _In_ ULONG Len,
    _In_ BOOLEAN High);

NTSTATUS
TcpChannelSendString(
    _Inout_ PTCP_CHANNEL Channel,
    _In_z_ const CHAR* Str,
    _In_ BOOLEAN High);

BOOLEAN
TcpChannelIsConnected(_In_ PTCP_CHANNEL Channel);
