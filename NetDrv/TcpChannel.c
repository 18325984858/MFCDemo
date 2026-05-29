/*++
    TcpChannel.c --- Kernel-mode WSK TCP channel object.
--*/

#include "TcpChannel.h"
#include "Wsk.h"
#include "../Shared/Protocol.h"
#include "../Shared/NdarkLog.h"
#include "CompatPool.h"
#include <ntstrsafe.h>

NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout);

#define TAG_TCP  'pctN'

extern volatile LONG g_ControlStop;   /* from NetControl.c */

static VOID
TcpSetAddr(_Out_ SOCKADDR_IN* a, UCHAR b1, UCHAR b2, UCHAR b3, UCHAR b4, USHORT port)
{
    RtlZeroMemory(a, sizeof(*a));
    a->sin_family = AF_INET;
    a->sin_port   = RtlUshortByteSwap(port);
    a->sin_addr.S_un.S_un_b.s_b1 = b1;
    a->sin_addr.S_un.S_un_b.s_b2 = b2;
    a->sin_addr.S_un.S_un_b.s_b3 = b3;
    a->sin_addr.S_un.S_un_b.s_b4 = b4;
}

static NTSTATUS
TcpRecvExact(_In_ PWSK_SOCKET Sock, _Out_writes_bytes_(Need) PVOID Buf, _In_ ULONG Need)
{
    ULONG got = 0;
    while (got < Need) {
        SIZE_T n = 0;
        NTSTATUS st = WSKReceive(Sock,
                                 (PUCHAR)Buf + got,
                                 (SIZE_T)(Need - got),
                                 &n, 0);
        if (!NT_SUCCESS(st))
            return st;
        if (n == 0)
            return STATUS_CONNECTION_RESET;
        got += (ULONG)n;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS
TcpSendRaw(_In_ PWSK_SOCKET Sock,
           _In_reads_bytes_(Len) const VOID* Buf,
           _In_ ULONG Len)
{
    ULONG sent = 0;
    while (sent < Len) {
        SIZE_T n = 0;
        NTSTATUS st = WSKSend(Sock,
                              (PVOID)((PUCHAR)Buf + sent),
                              (SIZE_T)(Len - sent),
                              &n, 0);
        if (!NT_SUCCESS(st))
            return st;
        if (n == 0)
            return STATUS_CONNECTION_RESET;
        sent += (ULONG)n;
    }
    return STATUS_SUCCESS;
}

static PWSK_SOCKET
TcpChannelBeginSend(_Inout_ PTCP_CHANNEL Channel)
{
    PWSK_SOCKET sock = NULL;

    ExAcquireFastMutex(&Channel->StateMutex);
    if (InterlockedCompareExchange(&Channel->Connected, 0, 0) != 0 &&
        InterlockedCompareExchange(&Channel->Closing, 0, 0) == 0 &&
        Channel->Socket) {
        sock = Channel->Socket;
        InterlockedIncrement(&Channel->ActiveSends);
        KeClearEvent(&Channel->SendIdleEvent);
    }
    ExReleaseFastMutex(&Channel->StateMutex);

    return sock;
}

static VOID
TcpChannelEndSend(_Inout_ PTCP_CHANNEL Channel)
{
    if (InterlockedDecrement(&Channel->ActiveSends) == 0)
        KeSetEvent(&Channel->SendIdleEvent, IO_NO_INCREMENT, FALSE);
}

static VOID
TcpChannelCloseIfCurrent(_Inout_ PTCP_CHANNEL Channel, _In_opt_ PWSK_SOCKET Sock)
{
    BOOLEAN closeIt = FALSE;

    if (!Sock)
        return;

    ExAcquireFastMutex(&Channel->StateMutex);
    if (Channel->Socket == Sock) {
        InterlockedExchange(&Channel->Closing, 1);
        Channel->Socket = NULL;
        InterlockedExchange(&Channel->Connected, 0);
        closeIt = TRUE;
    }
    ExReleaseFastMutex(&Channel->StateMutex);

    if (closeIt) {
        WSK_closesocket(Sock);
        if (InterlockedCompareExchange(&Channel->ActiveSends, 0, 0) != 0) {
            KeWaitForSingleObject(&Channel->SendIdleEvent, Executive,
                                  KernelMode, FALSE, NULL);
        }
    }
}

static VOID
TcpChannelCloseCurrent(_Inout_ PTCP_CHANNEL Channel)
{
    PWSK_SOCKET sock;

    ExAcquireFastMutex(&Channel->StateMutex);
    sock = Channel->Socket;
    if (sock)
        InterlockedExchange(&Channel->Closing, 1);
    Channel->Socket = NULL;
    InterlockedExchange(&Channel->Connected, 0);
    ExReleaseFastMutex(&Channel->StateMutex);

    if (sock) {
        WSK_closesocket(sock);
        if (InterlockedCompareExchange(&Channel->ActiveSends, 0, 0) != 0) {
            KeWaitForSingleObject(&Channel->SendIdleEvent, Executive,
                                  KernelMode, FALSE, NULL);
        }
    }
}

static NTSTATUS
TcpDoAuth(_In_ PWSK_SOCKET Sock)
{
    NTSTATUS st;
    UCHAR hdr[NETDRV_TCP_FRAME_HDR_SIZE];
    CHAR  ack[4];
    ULONG ackLen;

    *(ULONG*)(hdr + 0) = NETDRV_TCP_FRAME_MAGIC;
    *(ULONG*)(hdr + 4) = NETDRV_TCP_AUTH_KEY_LEN;

    st = TcpSendRaw(Sock, hdr, NETDRV_TCP_FRAME_HDR_SIZE);
    if (NT_SUCCESS(st))
        st = TcpSendRaw(Sock, NETDRV_TCP_AUTH_KEY, NETDRV_TCP_AUTH_KEY_LEN);
    if (!NT_SUCCESS(st))
        return st;

    st = TcpRecvExact(Sock, hdr, NETDRV_TCP_FRAME_HDR_SIZE);
    if (!NT_SUCCESS(st))
        return st;

    if (*(ULONG*)hdr != NETDRV_TCP_FRAME_MAGIC)
        return STATUS_LOGON_FAILURE;

    ackLen = *(ULONG*)(hdr + 4);
    if (ackLen == 0 || ackLen > sizeof(ack))
        return STATUS_LOGON_FAILURE;

    st = TcpRecvExact(Sock, ack, ackLen);
    if (!NT_SUCCESS(st))
        return st;

    if (ack[0] != '1')
        return STATUS_LOGON_FAILURE;

    return STATUS_SUCCESS;
}

static VOID
TcpRecvLoop(_Inout_ PTCP_CHANNEL Channel, _In_ PWSK_SOCKET Sock)
{
    NTSTATUS st;
    UCHAR    hdr[NETDRV_TCP_FRAME_HDR_SIZE];
    PUCHAR   frameBuf = NULL;
    ULONG    frameBufCap = 0;

    while (InterlockedCompareExchange(&Channel->Stop, 0, 0) == 0 &&
           InterlockedCompareExchange(&g_ControlStop, 0, 0) == 0)
    {
        st = TcpRecvExact(Sock, hdr, NETDRV_TCP_FRAME_HDR_SIZE);
        if (!NT_SUCCESS(st))
            break;

        ULONG magic  = *(ULONG*)(hdr + 0);
        ULONG payLen = *(ULONG*)(hdr + 4);

        if (magic != NETDRV_TCP_FRAME_MAGIC || payLen > NETDRV_TCP_MAX_FRAME_SIZE)
            break;

        if (payLen == 0)
            continue;

        if (payLen + 1 > frameBufCap) {
            if (frameBuf)
                ExFreePoolWithTag(frameBuf, TAG_TCP);
            frameBufCap = payLen + 1;
            if (frameBufCap < 4096)
                frameBufCap = 4096;
            frameBuf = (PUCHAR)ExAllocatePool2(POOL_FLAG_PAGED, frameBufCap, TAG_TCP);
            if (!frameBuf) {
                frameBufCap = 0;
                break;
            }
        }

        st = TcpRecvExact(Sock, frameBuf, payLen);
        if (!NT_SUCCESS(st))
            break;

        frameBuf[payLen] = 0;
        if (Channel->Dispatch)
            Channel->Dispatch((const CHAR*)frameBuf, payLen);
    }

    if (frameBuf)
        ExFreePoolWithTag(frameBuf, TAG_TCP);
}

static VOID
TcpChannelThread(_In_opt_ PVOID Context)
{
    PTCP_CHANNEL channel = (PTCP_CHANNEL)Context;
    LARGE_INTEGER delay;

    delay.QuadPart = -30000000LL;

    while (InterlockedCompareExchange(&channel->Stop, 0, 0) == 0 &&
           InterlockedCompareExchange(&g_ControlStop, 0, 0) == 0)
    {
        PWSK_SOCKET sock = NULL;
        SOCKADDR_IN peer;
        NTSTATUS st;

        st = WSK_socket(&sock, AF_INET, SOCK_STREAM, IPPROTO_TCP,
                        WSK_FLAG_CONNECTION_SOCKET);
        if (!NT_SUCCESS(st)) {
            KeWaitForSingleObject(&channel->StopEvent, Executive,
                                  KernelMode, FALSE, &delay);
            continue;
        }

        TcpSetAddr(&peer,
                   NETDRV_APP_IP_B1, NETDRV_APP_IP_B2,
                   NETDRV_APP_IP_B3, NETDRV_APP_IP_B4,
                   channel->Port);

        st = WSKConnect(sock, (PSOCKADDR)&peer);
        if (!NT_SUCCESS(st)) {
            WSK_closesocket(sock);
            KeWaitForSingleObject(&channel->StopEvent, Executive,
                                  KernelMode, FALSE, &delay);
            continue;
        }

        if (InterlockedCompareExchange(&channel->Stop, 0, 0) != 0 ||
            InterlockedCompareExchange(&g_ControlStop, 0, 0) != 0) {
            WSK_closesocket(sock);
            break;
        }

        ExAcquireFastMutex(&channel->StateMutex);
        InterlockedExchange(&channel->Closing, 0);
        channel->Socket = sock;
        ExReleaseFastMutex(&channel->StateMutex);

        st = TcpDoAuth(sock);
        if (!NT_SUCCESS(st)) {
            NDARK_LOG_WARN("tcp[%s] auth failed 0x%08X", channel->Name, st);
            TcpChannelCloseIfCurrent(channel, sock);
            KeWaitForSingleObject(&channel->StopEvent, Executive,
                                  KernelMode, FALSE, &delay);
            continue;
        }

        InterlockedExchange(&channel->Connected, 1);
        NDARK_LOG_INFO("tcp[%s] connected to %s:%u, auth ok",
                       channel->Name, NETDRV_APP_IP_A, channel->Port);

        if (channel->SendHello)
            TcpChannelSendString(channel, NETDRV_REG_HELLO, TRUE);

        TcpRecvLoop(channel, sock);
        NDARK_LOG_INFO("tcp[%s] disconnected, will retry", channel->Name);
        TcpChannelCloseIfCurrent(channel, sock);

        if (InterlockedCompareExchange(&channel->Stop, 0, 0) == 0)
            KeWaitForSingleObject(&channel->StopEvent, Executive,
                                  KernelMode, FALSE, &delay);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID
TcpSendQueueDrain(_Inout_ PTCP_CHANNEL Channel)
{
    ExAcquireFastMutex(&Channel->SendMutex);
    while (!IsListEmpty(&Channel->SendListHigh)) {
        PLIST_ENTRY e = RemoveHeadList(&Channel->SendListHigh);
        ExFreePoolWithTag(CONTAINING_RECORD(e, TCP_SEND_ITEM, Link), TAG_TCP);
    }
    while (!IsListEmpty(&Channel->SendListNorm)) {
        PLIST_ENTRY e = RemoveHeadList(&Channel->SendListNorm);
        ExFreePoolWithTag(CONTAINING_RECORD(e, TCP_SEND_ITEM, Link), TAG_TCP);
    }
    ExReleaseFastMutex(&Channel->SendMutex);
}

static BOOLEAN
TcpSendOneItem(_Inout_ PTCP_CHANNEL Channel)
{
    PTCP_SEND_ITEM item = NULL;
    PWSK_SOCKET sock;

    ExAcquireFastMutex(&Channel->SendMutex);
    if (!IsListEmpty(&Channel->SendListHigh)) {
        PLIST_ENTRY e = RemoveHeadList(&Channel->SendListHigh);
        item = CONTAINING_RECORD(e, TCP_SEND_ITEM, Link);
    } else if (!IsListEmpty(&Channel->SendListNorm)) {
        PLIST_ENTRY e = RemoveHeadList(&Channel->SendListNorm);
        item = CONTAINING_RECORD(e, TCP_SEND_ITEM, Link);
    }
    ExReleaseFastMutex(&Channel->SendMutex);

    if (!item)
        return FALSE;

    sock = TcpChannelBeginSend(Channel);
    if (sock) {
        UCHAR hdr[NETDRV_TCP_FRAME_HDR_SIZE];
        NTSTATUS st;

        *(ULONG*)(hdr + 0) = NETDRV_TCP_FRAME_MAGIC;
        *(ULONG*)(hdr + 4) = item->Len;

        st = TcpSendRaw(sock, hdr, NETDRV_TCP_FRAME_HDR_SIZE);
        if (NT_SUCCESS(st))
            st = TcpSendRaw(sock, item->Data, item->Len);
        TcpChannelEndSend(Channel);
        if (!NT_SUCCESS(st))
            TcpChannelCloseIfCurrent(Channel, sock);
    }

    ExFreePoolWithTag(item, TAG_TCP);
    return TRUE;
}

static VOID
TcpSendWorker(_In_opt_ PVOID Context)
{
    PTCP_CHANNEL channel = (PTCP_CHANNEL)Context;
    LARGE_INTEGER timeout;

    timeout.QuadPart = -10000000LL;

    while (InterlockedCompareExchange(&channel->Stop, 0, 0) == 0) {
        KeWaitForSingleObject(&channel->SendEvent, Executive,
                              KernelMode, FALSE, &timeout);
        if (InterlockedCompareExchange(&channel->Stop, 0, 0) != 0)
            break;

        while (TcpSendOneItem(channel)) {
            if (InterlockedCompareExchange(&channel->Stop, 0, 0) != 0)
                break;
        }
    }

    TcpSendQueueDrain(channel);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

VOID
TcpChannelInit(_Out_ PTCP_CHANNEL Channel,
               _In_z_ PCSTR Name,
               _In_ USHORT Port,
               _In_opt_ TCP_CHANNEL_DISPATCH Dispatch,
               _In_ BOOLEAN SendHello)
{
    RtlZeroMemory(Channel, sizeof(*Channel));
    Channel->Name = Name;
    Channel->Port = Port;
    Channel->Dispatch = Dispatch;
    Channel->SendHello = SendHello;
}

NTSTATUS
TcpChannelStart(_Inout_ PTCP_CHANNEL Channel)
{
    NTSTATUS st;

    if (Channel->ConnectThread)
        return STATUS_SUCCESS;

    InterlockedExchange(&Channel->Stop, 0);
    InterlockedExchange(&Channel->Connected, 0);
    InterlockedExchange(&Channel->Closing, 0);
    InterlockedExchange(&Channel->ActiveSends, 0);
    Channel->Socket = NULL;
    InitializeListHead(&Channel->SendListHigh);
    InitializeListHead(&Channel->SendListNorm);
    ExInitializeFastMutex(&Channel->SendMutex);
    ExInitializeFastMutex(&Channel->StateMutex);
    KeInitializeEvent(&Channel->StopEvent, NotificationEvent, FALSE);
    KeInitializeEvent(&Channel->SendEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&Channel->SendIdleEvent, NotificationEvent, TRUE);

    st = PsCreateSystemThread(&Channel->ConnectThread, THREAD_ALL_ACCESS,
                              NULL, NULL, NULL, TcpChannelThread, Channel);
    if (!NT_SUCCESS(st)) {
        Channel->ConnectThread = NULL;
        return st;
    }

    st = PsCreateSystemThread(&Channel->SendThread, THREAD_ALL_ACCESS,
                              NULL, NULL, NULL, TcpSendWorker, Channel);
    if (!NT_SUCCESS(st)) {
        Channel->SendThread = NULL;
        TcpChannelStop(Channel);
        return st;
    }

    return STATUS_SUCCESS;
}

VOID
TcpChannelStop(_Inout_ PTCP_CHANNEL Channel)
{
    if (!Channel->ConnectThread && !Channel->SendThread)
        return;

    InterlockedExchange(&Channel->Stop, 1);
    KeSetEvent(&Channel->StopEvent, IO_NO_INCREMENT, FALSE);
    KeSetEvent(&Channel->SendEvent, IO_NO_INCREMENT, FALSE);
    TcpChannelCloseCurrent(Channel);

    if (Channel->ConnectThread) {
        ZwWaitForSingleObject(Channel->ConnectThread, FALSE, NULL);
        ZwClose(Channel->ConnectThread);
        Channel->ConnectThread = NULL;
    }

    if (Channel->SendThread) {
        ZwWaitForSingleObject(Channel->SendThread, FALSE, NULL);
        ZwClose(Channel->SendThread);
        Channel->SendThread = NULL;
    }

    TcpSendQueueDrain(Channel);
    InterlockedExchange(&Channel->Connected, 0);
}

NTSTATUS
TcpChannelSend(_Inout_ PTCP_CHANNEL Channel,
               _In_reads_bytes_(Len) const VOID* Data,
               _In_ ULONG Len,
               _In_ BOOLEAN High)
{
    PTCP_SEND_ITEM item;
    BOOLEAN canQueue;

    if (!Data || Len == 0)
        return STATUS_INVALID_PARAMETER;
    if (Len > NETDRV_TCP_MAX_FRAME_SIZE)
        return STATUS_INVALID_BUFFER_SIZE;

    ExAcquireFastMutex(&Channel->StateMutex);
    canQueue = (BOOLEAN)(InterlockedCompareExchange(&Channel->Connected, 0, 0) != 0 &&
                         InterlockedCompareExchange(&Channel->Closing, 0, 0) == 0 &&
                         Channel->Socket != NULL);
    ExReleaseFastMutex(&Channel->StateMutex);
    if (!canQueue)
        return STATUS_CONNECTION_DISCONNECTED;

    item = (PTCP_SEND_ITEM)ExAllocatePool2(POOL_FLAG_PAGED,
        FIELD_OFFSET(TCP_SEND_ITEM, Data) + Len, TAG_TCP);
    if (!item)
        return STATUS_INSUFFICIENT_RESOURCES;

    item->Len = Len;
    RtlCopyMemory(item->Data, Data, Len);

    ExAcquireFastMutex(&Channel->SendMutex);
    InsertTailList(High ? &Channel->SendListHigh : &Channel->SendListNorm,
                   &item->Link);
    ExReleaseFastMutex(&Channel->SendMutex);

    KeSetEvent(&Channel->SendEvent, IO_NO_INCREMENT, FALSE);
    return STATUS_SUCCESS;
}

NTSTATUS
TcpChannelSendString(_Inout_ PTCP_CHANNEL Channel,
                     _In_z_ const CHAR* Str,
                     _In_ BOOLEAN High)
{
    return TcpChannelSend(Channel, Str, (ULONG)strlen(Str), High);
}

BOOLEAN
TcpChannelIsConnected(_In_ PTCP_CHANNEL Channel)
{
    return (BOOLEAN)(InterlockedCompareExchange(&Channel->Connected, 0, 0) != 0);
}
