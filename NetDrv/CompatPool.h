/*++
    CompatPool.h --- Pool allocation compatibility shim.

    ExAllocatePool2 / POOL_FLAG_* are only exported by ntoskrnl.exe starting
    with Windows 10 version 2004 (build 19041). On older systems the import
    is unresolved and the driver fails to load with STATUS_ENTRYPOINT_NOT_FOUND
    (presented by Service Control Manager as error 127 "the specified
    procedure could not be found").

    To keep one set of source while still supporting Win7+/Win10 LTSC 2019,
    we route ExAllocatePool2 to the legacy ExAllocatePoolWithTag, mapping
    POOL_FLAG_NON_PAGED -> NonPagedPoolNx (DEP-friendly, available since
    Win8) and POOL_FLAG_PAGED -> PagedPool.

    Include this header AFTER <ntddk.h>/<wdm.h> in every translation unit
    that allocates pool memory.
--*/
#pragma once

#include <ntddk.h>

/* MSVC marks the legacy ExAllocatePoolWithTag as deprecated (C4996) in newer
   WDKs. Our shim deliberately routes back to it for compatibility with
   pre-19041 kernels, so silence the warning project-wide once this header is
   included. */
#pragma warning(disable: 4996)

/* Map POOL_FLAG_* tokens to legacy POOL_TYPE values. We deliberately stay
   inside the enum range so MSVC does not warn about implicit conversions. */
#ifndef NDARK_POOL_COMPAT_DEFINED
#define NDARK_POOL_COMPAT_DEFINED 1

/* Some headers may have already typedef'd POOL_FLAG_* as ULONG64; we shadow
   them with macros that ExAllocatePoolWithTag understands. */
#undef  POOL_FLAG_NON_PAGED
#undef  POOL_FLAG_PAGED
#undef  POOL_FLAG_NON_PAGED_EXECUTE
#undef  POOL_FLAG_USE_QUOTA

#define POOL_FLAG_NON_PAGED          ((POOL_TYPE)NonPagedPoolNx)
#define POOL_FLAG_PAGED              ((POOL_TYPE)PagedPool)
#define POOL_FLAG_NON_PAGED_EXECUTE  ((POOL_TYPE)NonPagedPoolExecute)
#define POOL_FLAG_USE_QUOTA          ((POOL_TYPE)NonPagedPoolNx)  /* quota dropped */

/* The shim. ExAllocatePool2(flags, size, tag) becomes
   ExAllocatePoolWithTag((POOL_TYPE)flags, size, tag). */
#define ExAllocatePool2(Flags, Size, Tag) \
    ExAllocatePoolWithTag((POOL_TYPE)(Flags), (Size), (Tag))

#endif /* NDARK_POOL_COMPAT_DEFINED */
