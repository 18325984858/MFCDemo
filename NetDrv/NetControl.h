#pragma once

#include <ntddk.h>

NTSTATUS NetDrvStartControlListener(VOID);
VOID NetDrvStopControlListener(VOID);