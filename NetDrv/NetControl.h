#pragma once

#include <ntddk.h>

extern volatile LONG g_ControlStop;

NTSTATUS NetDrvStartControlListener(VOID);
VOID NetDrvStopControlListener(VOID);

/* Dispatch a command payload (same format as UDP post-magic).
   Called by TcpLink receive loop.  Thread-safe. */
VOID NetDrvDispatchCommand(_In_reads_bytes_(Len) const CHAR* Payload, _In_ ULONG Len);