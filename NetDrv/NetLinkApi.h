/*++
    NetLinkApi.h --- C/C++ boundary entry points for NetLink-based links.

    C files (Driver.c / NetControl.c / TcpLink.c / EnumArk.c / ScreenShot.c)
    interact with NetLinkBase-derived objects only through this header; they
    must not include "NetLink.h" directly.

    This header is C-clean (no class, no template). The C++ side exposes the
    implementations with extern "C" linkage.

    Skeleton phase: this header declares only a runtime self-test entry that
    Driver.c calls in DriverEntry to force the C++ translation units to be
    pulled into the final NetDrv.sys. The real factory functions
    (NetDrvCreateUdpLink, NetDrvCreateTcpChannel, NetDrvLinkSend, ...) will
    be added in a follow-up step alongside UdpLink.cpp / TcpLinkChannel.cpp.
    Until then, NetControl.c / TcpLink.c / TcpChannel.c keep their existing
    behaviour unchanged.
--*/
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <ntddk.h>

/// Opaque handle: actually points to a NetLinkBase-derived object.
typedef struct _NETLINK_HANDLE_OPAQUE* NETLINK_HANDLE;

// ----------------------------------------------------------------------
// Factory API (enabled in the next migration step)
// ----------------------------------------------------------------------
//
// NTSTATUS NetDrvCreateUdpLink     (_Out_ NETLINK_HANDLE* OutLink);
// NTSTATUS NetDrvCreateTcpChannel  (_In_ int ChannelId,
//                                   _Out_ NETLINK_HANDLE* OutLink);
// VOID     NetDrvDestroyLink       (_Inout_ NETLINK_HANDLE* InOutLink);
//
// NTSTATUS NetDrvLinkConnect       (_In_ NETLINK_HANDLE Link);
// NTSTATUS NetDrvLinkSend          (_In_ NETLINK_HANDLE Link,
//                                   _In_reads_bytes_(Len) const VOID* Data,
//                                   _In_ ULONG Len);
// BOOLEAN  NetDrvLinkIsConnected   (_In_ NETLINK_HANDLE Link);

// ----------------------------------------------------------------------
// Skeleton phase: a single self-test entry that touches placement new and
// the vtable, ensuring the C++ runtime stubs link successfully.
// ----------------------------------------------------------------------
NTSTATUS NetLinkRuntimeSelfTest(VOID);

#ifdef __cplusplus
}
#endif
