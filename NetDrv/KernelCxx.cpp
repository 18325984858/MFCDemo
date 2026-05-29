/*++
    KernelCxx.cpp --- Kernel-mode C++ runtime stubs.

    Every kernel .cpp built into NetDrv.sys requires:
      - _purecall stub: catches calls through a vtable on an object that is
        not fully constructed (or already destructed). We bugcheck on the spot
        so the issue is visible in a crash dump rather than corrupting state.
      - Deleted operator new/new[]/delete/delete[]: kernel mode has no C++
        heap. Any unintended use is now a compile-time error.
      - Placement new: WDK does not ship <new>; we provide our own in
        NetLink.h (inline) so this file does not need to repeat it.

    This file has no global constructors, no STL, no exceptions, no RTTI.
--*/

extern "C" {
#include <ntddk.h>
}

// KeBugCheckEx is noreturn; statements after it are unreachable by design.
#pragma warning(disable: 4702)

// ---------------------------------------------------------------------------
// _purecall: pure virtual call bugcheck stub.
// ---------------------------------------------------------------------------
extern "C" int __cdecl _purecall(void)
{
    // 0xE2 = MANUALLY_INITIATED_CRASH; custom param 0xC1170001 ("C++ 0001")
    // makes it easy to identify the cause in !analyze -v.
    KeBugCheckEx(0xE2u, 0xC1170001u, 0, 0, 0);
    return 0;
}

// ---------------------------------------------------------------------------
// Stub operator new/delete: there is no kernel C++ heap. MSVC pre-declares
// these implicitly so we cannot use `= delete`; instead we provide stub
// implementations that bugcheck on the spot. The intent is the same -- any
// use of plain new/delete in kernel C++ code is a bug.
// All kernel C++ code must allocate with ExAllocatePool2 and construct with
// placement new (declared in NetLink.h).
// ---------------------------------------------------------------------------
void* __cdecl operator new(size_t)
{
    KeBugCheckEx(0xE2u, 0xC1170002u, 0, 0, 0);
    return nullptr;
}
void* __cdecl operator new[](size_t)
{
    KeBugCheckEx(0xE2u, 0xC1170003u, 0, 0, 0);
    return nullptr;
}
void __cdecl operator delete(void*) noexcept
{
    KeBugCheckEx(0xE2u, 0xC1170004u, 0, 0, 0);
}
void __cdecl operator delete[](void*) noexcept
{
    KeBugCheckEx(0xE2u, 0xC1170005u, 0, 0, 0);
}
void __cdecl operator delete(void*, size_t) noexcept
{
    KeBugCheckEx(0xE2u, 0xC1170006u, 0, 0, 0);
}
void __cdecl operator delete[](void*, size_t) noexcept
{
    KeBugCheckEx(0xE2u, 0xC1170007u, 0, 0, 0);
}
