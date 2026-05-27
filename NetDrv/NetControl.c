#include "NetControl.h"
#include "Wsk.h"
#include "Ioctl.h"
#include "EnumArk.h"
#include "ScreenShot.h"
#include <ntstrsafe.h>

#define LOG(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, \
                                 "[NetDrv] " fmt "\n", ##__VA_ARGS__)

NTSYSAPI NTSTATUS NTAPI ZwWaitForSingleObject(
    _In_ HANDLE Handle,
    _In_ BOOLEAN Alertable,
    _In_opt_ PLARGE_INTEGER Timeout);

static HANDLE g_ControlThread = NULL;
static volatile LONG g_ControlStop = 0;
static KEVENT g_CommandEvent;
static KSPIN_LOCK g_CommandLock;

/* Async thread tracking: count active threads, signal when all done. */
static volatile LONG g_AsyncCount = 0;
static KEVENT g_AsyncDone;

// Command FIFO. Each slot holds one datagram (post-magic). A single slot was
// fine when only sparse control commands flowed, but file upload sends thousands
// of P| chunks back-to-back, so we need a queue to avoid drops.
#define NETDRV_CMD_QUEUE_DEPTH  128
#define NETDRV_CMD_SLOT_BYTES   2048

static CHAR  g_CmdQueue[NETDRV_CMD_QUEUE_DEPTH][NETDRV_CMD_SLOT_BYTES];
static ULONG g_CmdHead = 0;
static ULONG g_CmdTail = 0;
static ULONG g_CmdDropped = 0;

static WSK_CLIENT_DATAGRAM_DISPATCH g_DatagramDispatch;
static CONST NPIID g_WskNpiId =
    { 0x2227E803, 0x8D8B, 0x11D4, { 0xAB, 0xAD, 0x00, 0x90, 0x27, 0x71, 0x9E, 0x09 } };

static VOID NetDrvSetAnySockAddr(_Out_ SOCKADDR_IN* addr, _In_ USHORT port)
{
    RtlZeroMemory(addr, sizeof(*addr));
    addr->sin_family = AF_INET;
    addr->sin_port = RtlUshortByteSwap(port);
}

static BOOLEAN NetDrvHasMagic(_In_reads_bytes_(len) const CHAR* buf, _In_ SIZE_T len)
{
    return len >= NETDRV_UDP_PACKET_MAGIC_LEN &&
           RtlCompareMemory(buf, NETDRV_UDP_PACKET_MAGIC,
                            NETDRV_UDP_PACKET_MAGIC_LEN) == NETDRV_UDP_PACKET_MAGIC_LEN;
}

/* ---- Async dispatch: heavy commands run in their own system thread ---- */

typedef struct _ASYNC_CMD {
    CHAR Command[NETDRV_CMD_SLOT_BYTES];
} ASYNC_CMD;

static VOID AsyncCmdThread(_In_ PVOID Context)
{
    ASYNC_CMD* ac = (ASYNC_CMD*)Context;
    PCSTR cmd = ac->Command;

    if (strncmp(cmd, NETDRV_CMD_ENUM_PROCESS, strlen(NETDRV_CMD_ENUM_PROCESS)) == 0) {
        (void)NetDrvEnumProcess();
    } else if (strncmp(cmd, NETDRV_CMD_ENUM_DRIVER, strlen(NETDRV_CMD_ENUM_DRIVER)) == 0) {
        (void)NetDrvEnumDriver();
    } else if (strncmp(cmd, NETDRV_CMD_ENUM_FILE, strlen(NETDRV_CMD_ENUM_FILE)) == 0) {
        (void)NetDrvEnumFile(cmd + strlen(NETDRV_CMD_ENUM_FILE));
    } else if (strncmp(cmd, NETDRV_CMD_GET_FILE, strlen(NETDRV_CMD_GET_FILE)) == 0) {
        (void)NetDrvGetFile(cmd + strlen(NETDRV_CMD_GET_FILE));
    } else if (strncmp(cmd, NETDRV_CMD_SCREENSHOT, strlen(NETDRV_CMD_SCREENSHOT)) == 0) {
        (void)NetDrvScreenCapture();
    }

    ExFreePoolWithTag(ac, 'dmcA');

    /* Decrement async count; signal if last thread done. */
    if (InterlockedDecrement(&g_AsyncCount) == 0)
        KeSetEvent(&g_AsyncDone, IO_NO_INCREMENT, FALSE);

    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID NetDrvDispatchAsync(_In_z_ PCSTR cmd)
{
    /* Reject if shutting down */
    if (InterlockedCompareExchange(&g_ControlStop, 0, 0) != 0) return;

    ASYNC_CMD* ac = (ASYNC_CMD*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(ASYNC_CMD), 'dmcA');
    if (!ac) { LOG("async dispatch: alloc failed"); return; }
    RtlStringCbCopyA(ac->Command, sizeof(ac->Command), cmd);

    InterlockedIncrement(&g_AsyncCount);

    HANDLE hThread = NULL;
    NTSTATUS st = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS,
        NULL, NULL, NULL, AsyncCmdThread, ac);
    if (NT_SUCCESS(st)) {
        ZwClose(hThread);
    } else {
        LOG("async dispatch: PsCreateSystemThread failed 0x%08X", st);
        ExFreePoolWithTag(ac, 'dmcA');
        if (InterlockedDecrement(&g_AsyncCount) == 0)
            KeSetEvent(&g_AsyncDone, IO_NO_INCREMENT, FALSE);
    }
}

static VOID NetDrvHandleCommand(_In_z_ PCSTR cmd)
{
    LOG("handle command '%.40s'", cmd);

    /* Heavy commands: dispatch to a dedicated thread */
    if (strncmp(cmd, NETDRV_CMD_ENUM_PROCESS, strlen(NETDRV_CMD_ENUM_PROCESS)) == 0 ||
        strncmp(cmd, NETDRV_CMD_ENUM_DRIVER, strlen(NETDRV_CMD_ENUM_DRIVER)) == 0 ||
        strncmp(cmd, NETDRV_CMD_ENUM_FILE, strlen(NETDRV_CMD_ENUM_FILE)) == 0 ||
        strncmp(cmd, NETDRV_CMD_GET_FILE, strlen(NETDRV_CMD_GET_FILE)) == 0 ||
        strncmp(cmd, NETDRV_CMD_SCREENSHOT, strlen(NETDRV_CMD_SCREENSHOT)) == 0)
    {
        NetDrvDispatchAsync(cmd);
        return;
    }

    /* Light commands: handle inline on the control thread */
    if (strncmp(cmd, NETDRV_CMD_PUT_END, strlen(NETDRV_CMD_PUT_END)) == 0) {
        (void)NetDrvPutEnd(cmd + strlen(NETDRV_CMD_PUT_END));
    } else if (strncmp(cmd, NETDRV_CMD_PUT_BEGIN, strlen(NETDRV_CMD_PUT_BEGIN)) == 0) {
        (void)NetDrvPutBegin(cmd + strlen(NETDRV_CMD_PUT_BEGIN));
    } else if (cmd[0] == 'P' && cmd[1] == '|') {
        (void)NetDrvPutChunk(cmd + 2);
    } else if (strncmp(cmd, NETDRV_CMD_STOP, strlen(NETDRV_CMD_STOP)) == 0) {
        LOG("UDP command: stop");
        InterlockedExchange(&g_ControlStop, 1);
    } else {
        LOG("UDP command ignored: unknown '%.40s'", cmd);
    }
}

static VOID NetDrvQueueCommand(_In_reads_bytes_(length) const CHAR* text,
                               _In_ SIZE_T length)
{
    KIRQL  oldIrql;
    SIZE_T copyLength;
    ULONG  nextHead;

    if (!NetDrvHasMagic(text, length)) {
        LOG("RX datagram dropped: invalid magic len=%Iu", length);
        return;
    }

    text += NETDRV_UDP_PACKET_MAGIC_LEN;
    length -= NETDRV_UDP_PACKET_MAGIC_LEN;
    copyLength = min(length, NETDRV_CMD_SLOT_BYTES - 1);

    KeAcquireSpinLock(&g_CommandLock, &oldIrql);
    nextHead = (g_CmdHead + 1) % NETDRV_CMD_QUEUE_DEPTH;
    if (nextHead == g_CmdTail) {
        // queue full: drop oldest so the freshest command is preserved
        g_CmdTail = (g_CmdTail + 1) % NETDRV_CMD_QUEUE_DEPTH;
        ++g_CmdDropped;
    }
    RtlCopyMemory(g_CmdQueue[g_CmdHead], text, copyLength);
    g_CmdQueue[g_CmdHead][copyLength] = 0;
    g_CmdHead = nextHead;
    KeReleaseSpinLock(&g_CommandLock, oldIrql);

    KeSetEvent(&g_CommandEvent, IO_NO_INCREMENT, FALSE);
}

static NTSTATUS NetDrvReceiveFromEvent(_In_opt_ PVOID SocketContext,
                                       _In_ ULONG Flags,
                                       _In_opt_ PWSK_DATAGRAM_INDICATION DataIndication)
{
    UNREFERENCED_PARAMETER(SocketContext);
    UNREFERENCED_PARAMETER(Flags);

    if (!DataIndication) {
        LOG("ReceiveFromEvent: NULL indication, stopping listener");
        InterlockedExchange(&g_ControlStop, 1);
        KeSetEvent(&g_CommandEvent, IO_NO_INCREMENT, FALSE);
        return STATUS_SUCCESS;
    }

    for (PWSK_DATAGRAM_INDICATION item = DataIndication; item; item = item->Next) {
        SIZE_T length = item->Buffer.Length;
        PUCHAR base = MmGetSystemAddressForMdlSafe(item->Buffer.Mdl,
                                                   NormalPagePriority | MdlMappingNoExecute);
        if (!base || length == 0) {
            LOG("ReceiveFromEvent: skip indication base=%p len=%Iu flags=0x%08X", base, length, Flags);
            continue;
        }

        LOG("ReceiveFromEvent: datagram len=%Iu offset=%u flags=0x%08X", length, item->Buffer.Offset, Flags);
        NetDrvQueueCommand((const CHAR*)(base + item->Buffer.Offset), length);
    }

    return STATUS_SUCCESS;
}

static NTSTATUS NetDrvEnableReceiveEvent(_In_ PWSK_SOCKET sock)
{
    WSK_EVENT_CALLBACK_CONTROL control;
    PWSK_PROVIDER_BASIC_DISPATCH dispatch;

    control.NpiId = (PNPIID)&g_WskNpiId;
    control.EventMask = WSK_EVENT_RECEIVE_FROM;

    dispatch = (PWSK_PROVIDER_BASIC_DISPATCH)sock->Dispatch;
    NTSTATUS status = dispatch->WskControlSocket(sock,
                                                 WskSetOption,
                                                 SO_WSK_EVENT_CALLBACK,
                                                 SOL_SOCKET,
                                                 sizeof(control),
                                                 &control,
                                                 0,
                                                 NULL,
                                                 NULL,
                                                 NULL);
    LOG("enable receive event status=0x%08X", status);
    return status;
}

static BOOLEAN NetDrvTakeCommand(_Out_writes_z_(capacity) PCHAR command,
                                 _In_ SIZE_T capacity)
{
    KIRQL oldIrql;
    BOOLEAN hasCommand;

    KeAcquireSpinLock(&g_CommandLock, &oldIrql);
    hasCommand = (g_CmdHead != g_CmdTail);
    if (hasCommand && capacity != 0) {
        RtlStringCbCopyA(command, capacity, g_CmdQueue[g_CmdTail]);
        g_CmdTail = (g_CmdTail + 1) % NETDRV_CMD_QUEUE_DEPTH;
    }
    KeReleaseSpinLock(&g_CommandLock, oldIrql);

    return hasCommand;
}

static VOID NetDrvControlThread(_In_opt_ PVOID Context)
{
    PWSK_SOCKET sock = NULL;
    SOCKADDR_IN local;
    SOCKADDR_IN appAddr;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(Context);

    status = WSK_socket_ex(&sock, AF_INET, SOCK_DGRAM, IPPROTO_UDP,
                           WSK_FLAG_DATAGRAM_SOCKET, NULL, &g_DatagramDispatch);
    if (!NT_SUCCESS(status)) {
        LOG("control WSK_socket failed 0x%08X", status);
        PsTerminateSystemThread(status);
    }

    /* Bind to DRIVER_IP with ephemeral port (driver is the client). */
    NetDrvSetAnySockAddr(&local, 0);
    local.sin_addr.S_un.S_un_b.s_b1 = NETDRV_DRIVER_IP_B1;
    local.sin_addr.S_un.S_un_b.s_b2 = NETDRV_DRIVER_IP_B2;
    local.sin_addr.S_un.S_un_b.s_b3 = NETDRV_DRIVER_IP_B3;
    local.sin_addr.S_un.S_un_b.s_b4 = NETDRV_DRIVER_IP_B4;
    status = WSKBind(sock, (PSOCKADDR)&local);
    if (!NT_SUCCESS(status)) {
        LOG("control bind %s:0 failed 0x%08X", NETDRV_DRIVER_IP_A, status);
        WSK_closesocket(sock);
        PsTerminateSystemThread(status);
    }

    LOG("control listening %s:* (driver ip %s)", NETDRV_DRIVER_IP_A, NETDRV_DRIVER_IP_A);

    status = NetDrvEnableReceiveEvent(sock);
    if (!NT_SUCCESS(status)) {
        LOG("enable receive event failed 0x%08X", status);
        WSK_closesocket(sock);
        PsTerminateSystemThread(status);
    }

    /* App server address. */
    RtlZeroMemory(&appAddr, sizeof(appAddr));
    appAddr.sin_family = AF_INET;
    appAddr.sin_port   = RtlUshortByteSwap(NETDRV_UDP_PORT);
    appAddr.sin_addr.S_un.S_un_b.s_b1 = NETDRV_APP_IP_B1;
    appAddr.sin_addr.S_un.S_un_b.s_b2 = NETDRV_APP_IP_B2;
    appAddr.sin_addr.S_un.S_un_b.s_b3 = NETDRV_APP_IP_B3;
    appAddr.sin_addr.S_un.S_un_b.s_b4 = NETDRV_APP_IP_B4;

    /* Send hello to register with app. */
    {
        CHAR hello[32];
        SIZE_T sent = 0;
        RtlStringCbCopyA(hello, sizeof(hello), NETDRV_UDP_PACKET_MAGIC NETDRV_REG_HELLO);
        WSKSendTo(sock, hello, strlen(hello), &sent, (PSOCKADDR)&appAddr);
        LOG("sent R|hello to %s:%u", NETDRV_APP_IP_A, NETDRV_UDP_PORT);
    }

    LOG("Ready: UDP control %s:* -> app %s:%u",
        NETDRV_DRIVER_IP_A,
        NETDRV_APP_IP_A,
        NETDRV_UDP_PORT);

    while (InterlockedCompareExchange(&g_ControlStop, 0, 0) == 0) {
        CHAR command[NETDRV_CMD_SLOT_BYTES];
        LARGE_INTEGER timeout;
        timeout.QuadPart = -50000000LL;  /* 5 seconds */

        status = KeWaitForSingleObject(&g_CommandEvent, Executive,
                                        KernelMode, FALSE, &timeout);

        if (InterlockedCompareExchange(&g_ControlStop, 0, 0) != 0)
            break;

        if (status == STATUS_TIMEOUT) {
            /* Heartbeat: send ping so app knows driver is still alive. */
            CHAR ping[32];
            SIZE_T sent = 0;
            RtlStringCbCopyA(ping, sizeof(ping), NETDRV_UDP_PACKET_MAGIC NETDRV_REG_PING);
            WSKSendTo(sock, ping, strlen(ping), &sent, (PSOCKADDR)&appAddr);
            continue;
        }

        /* Drain the command queue. */
        while (NetDrvTakeCommand(command, sizeof(command))) {
            NetDrvHandleCommand(command);
        }
    }

    WSK_closesocket(sock);
    LOG("control stopped");
    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS NetDrvStartControlListener(VOID)
{
    NTSTATUS status;

    if (g_ControlThread) {
        LOG("control listener already started");
        return STATUS_SUCCESS;
    }

    InterlockedExchange(&g_ControlStop, 0);
    KeInitializeEvent(&g_CommandEvent, SynchronizationEvent, FALSE);
    KeInitializeEvent(&g_AsyncDone, NotificationEvent, TRUE);  /* initially signaled = no threads */
    KeInitializeSpinLock(&g_CommandLock);
    g_CmdHead = 0;
    g_CmdTail = 0;
    g_CmdDropped = 0;
    RtlZeroMemory(&g_DatagramDispatch, sizeof(g_DatagramDispatch));
    g_DatagramDispatch.WskReceiveFromEvent = NetDrvReceiveFromEvent;

    status = PsCreateSystemThread(&g_ControlThread,
                                  THREAD_ALL_ACCESS,
                                  NULL,
                                  NULL,
                                  NULL,
                                  NetDrvControlThread,
                                  NULL);
    if (!NT_SUCCESS(status)) {
        g_ControlThread = NULL;
        LOG("PsCreateSystemThread failed 0x%08X", status);
    } else {
        LOG("control listener thread created handle=%p", g_ControlThread);
    }
    return status;
}

VOID NetDrvStopControlListener(VOID)
{
    if (!g_ControlThread) {
        LOG("control listener stop skipped: no thread");
        return;
    }

    LOG("control listener stopping");
    InterlockedExchange(&g_ControlStop, 1);
    KeSetEvent(&g_CommandEvent, IO_NO_INCREMENT, FALSE);
    ZwWaitForSingleObject(g_ControlThread, FALSE, NULL);
    ZwClose(g_ControlThread);
    g_ControlThread = NULL;

    /* Wait for all async command threads to finish */
    if (InterlockedCompareExchange(&g_AsyncCount, 0, 0) > 0) {
        LOG("waiting for %ld async threads...", g_AsyncCount);
        LARGE_INTEGER timeout;
        timeout.QuadPart = -100000000LL;  /* 10 seconds max */
        KeWaitForSingleObject(&g_AsyncDone, Executive, KernelMode, FALSE, &timeout);
    }
    LOG("all async threads done, async count=%ld", g_AsyncCount);
}


//netsh advfirewall firewall add rule name="NetDrv UDP 9999 In" dir=in action=allow protocol=UDP localport=9999
//netsh advfirewall firewall add rule name="ArkApp UDP 9999 In" dir=in action=allow protocol=UDP localport=9999


//netsh advfirewall firewall add rule name="ArkApp UDP 9998 In" dir=in action=allow protocol=UDP localport=9998