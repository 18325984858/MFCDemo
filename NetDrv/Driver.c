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

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     NetDrvUnload;

#define LOG(fmt, ...) /* disabled */

// ---------------------------------------------------------------------------

VOID
NetDrvUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    LOG("Unload");
    NetDrvScreenCleanup();
    NetDrvStopControlListener();
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

    status = NetDrvStartControlListener();
    if (!NT_SUCCESS(status)) {
        LOG("NetDrvStartControlListener failed 0x%08X", status);
        WSKCleanup();
        return status;
    }

    LOG("Ready: UDP control %s:%u -> app %s:%u",
        NETDRV_DRIVER_IP_A,
        NETDRV_UDP_PORT,
        NETDRV_APP_IP_A,
        NETDRV_UDP_PORT);
    return STATUS_SUCCESS;
}
