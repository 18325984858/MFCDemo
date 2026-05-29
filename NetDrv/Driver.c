/*++

Module Name:

    Driver.c

Abstract:

        NetDrv: pure UDP ARK-style enumerator. It listens on
        NETDRV_DRIVER_IP:NETDRV_UDP_PORT for command packets and streams results
        back to user mode over UDP NETDRV_APP_IP:NETDRV_UDP_PORT.

--*/

#include "Wsk.h"
#include "Ioctl.h"
#include "NetControl.h"
#include "ScreenShot.h"
#include "TcpLink.h"
#include "NetLinkApi.h"

#include "../Shared/NdarkLog.h"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     NetDrvUnload;

#define LOG(fmt, ...) NDARK_LOG_INFO(fmt, ##__VA_ARGS__)

// ---------------------------------------------------------------------------

VOID
NetDrvUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    LOG("Unload");
    NetDrvStopControlListener();
    TcpLinkStop();
    NetDrvScreenCleanup();
    WSKCleanup();
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;

    LOG("DriverEntry");

    // Register the unload routine so `sc stop NetDrv` can tear us down cleanly.
    DriverObject->DriverUnload = NetDrvUnload;

    status = WSKStartup(MAKE_WSK_VERSION(1, 0));
    if (!NT_SUCCESS(status)) {
        LOG("WSKStartup failed 0x%08X", status);
        return status;
    }

    /* C++ runtime self-test: ensures NetLink.cpp/KernelCxx.cpp are linked
       into the final .sys. Skeleton phase only exercises placement new and
       vtable dispatch; future revisions will replace this with the real
       NetDrvCreateUdpLink / NetDrvCreateTcpChannel factory calls. */
#ifndef NDARK_NO_CPP
    (void)NetLinkRuntimeSelfTest();
#endif

    status = NetDrvStartControlListener();
    if (!NT_SUCCESS(status)) {
        LOG("NetDrvStartControlListener failed 0x%08X", status);
        WSKCleanup();
        return status;
    }

    status = TcpLinkStart();
    if (!NT_SUCCESS(status)) {
        LOG("TcpLinkStart failed 0x%08X", status);
        /* Non-fatal: UDP still works */
    }

    LOG("Ready: UDP %s:%u  TCP control/screen/file -> %s:%u/%u/%u",
        NETDRV_DRIVER_IP_A,
        NETDRV_UDP_PORT,
        NETDRV_APP_IP_A,
        NETDRV_TCP_CONTROL_PORT,
        NETDRV_TCP_SCREEN_PORT,
        NETDRV_TCP_FILE_PORT);
    return STATUS_SUCCESS;
}
