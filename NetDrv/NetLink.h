/*++
    NetLink.h --- Kernel-mode C++ abstract base for Network ARK links.

    Used only inside .cpp files that opt into the C++ subset. C files should
    include "NetLinkApi.h" instead.

    Constraints (kernel C++ island, "level B"):
      - No STL, no exceptions, no RTTI
      - No global object auto-construction: derived instances must be placed
        with placement new into static storage allocated in .bss
      - All WSK / DRIVER_OBJECT callbacks remain extern "C" free functions
        that downcast a context pointer to NetLinkBase* and forward.

    The six contract methods mirror QtApp::NetLinkBase exactly so that the
    user-mode side and kernel side share the same mental model.
--*/
#pragma once

extern "C" {
#include <ntddk.h>
#include <wsk.h>
}

// WDK does not ship <new>; supply our own placement new / delete.
inline void* __cdecl operator new  (size_t, void* p) noexcept { return p; }
inline void* __cdecl operator new[](size_t, void* p) noexcept { return p; }
inline void  __cdecl operator delete  (void*, void*) noexcept {}
inline void  __cdecl operator delete[](void*, void*) noexcept {}

// Pool tag: 'kniL' = "Link"
#define NETLINK_POOL_TAG  'kniL'

class NetLinkBase
{
public:
    NetLinkBase() = default;
    virtual ~NetLinkBase() = default;

    // Non-copyable, non-movable: an instance owns a socket and threads.
    NetLinkBase(const NetLinkBase&)            = delete;
    NetLinkBase& operator=(const NetLinkBase&) = delete;

    // ------------------------------------------------------------------
    // Six contract methods
    // ------------------------------------------------------------------

    /// 1. Connect: create socket, bind/connect, perform TCP handshake.
    virtual NTSTATUS Connect() = 0;

    /// 2. Heartbeat: invoked periodically by a shared dispatcher thread.
    virtual NTSTATUS Heartbeat() = 0;

    /// 3. RecvPacket: extract one business payload from the wire into
    ///    outBuf. UDP / TCP perform the actual receive inside their own
    ///    event callback / receive loop; this method is a polling-style
    ///    placeholder that may simply return STATUS_NOT_SUPPORTED for now.
    virtual NTSTATUS RecvPacket(_Out_writes_bytes_(Cap) PVOID outBuf,
                                _In_ ULONG Cap,
                                _Out_ PULONG outLen) = 0;

    /// 4. SendPacket: BuildPacket -> SendRaw. Default impl below.
    virtual NTSTATUS SendPacket(_In_reads_bytes_(Len) const VOID* payload,
                                _In_ ULONG Len);

    /// 5. VerifyPacket: magic / length / AUTH check.
    virtual BOOLEAN  VerifyPacket(_In_reads_bytes_(Len) const VOID* bytes,
                                  _In_ ULONG Len) const = 0;

    /// 6. BuildPacket: wrap payload into wire bytes inside outBuf.
    virtual NTSTATUS BuildPacket(_In_reads_bytes_(payLen) const VOID* payload,
                                 _In_ ULONG payLen,
                                 _Out_writes_bytes_(Cap) PVOID outBuf,
                                 _In_ ULONG Cap,
                                 _Out_ PULONG outLen) const = 0;

    // ------------------------------------------------------------------
    // Common state
    // ------------------------------------------------------------------
    BOOLEAN IsConnected() const
    {
        return InterlockedCompareExchange(
            const_cast<volatile LONG*>(&m_Connected), 0, 0) != 0;
    }
    PCSTR LinkName() const { return m_Name ? m_Name : "?"; }

protected:
    /// Concrete sink: actually push bytes onto the socket.
    virtual NTSTATUS SendRaw(_In_reads_bytes_(Len) const VOID* bytes,
                             _In_ ULONG Len) = 0;

    void SetConnected(BOOLEAN ok)
    {
        InterlockedExchange(&m_Connected, ok ? 1 : 0);
    }

    void SetName(PCSTR name) { m_Name = name; }

private:
    volatile LONG m_Connected = 0;
    PCSTR         m_Name      = nullptr;
};

// Default SendPacket: stack-buffered build then SendRaw. Subclasses can
// override for large frames (pool-backed buffer).
inline NTSTATUS NetLinkBase::SendPacket(_In_reads_bytes_(Len) const VOID* payload,
                                       _In_ ULONG Len)
{
    if (!IsConnected()) return STATUS_DEVICE_NOT_READY;

    UCHAR  stackBuf[2048];
    ULONG  outLen = 0;
    NTSTATUS st = BuildPacket(payload, Len, stackBuf, sizeof(stackBuf), &outLen);
    if (!NT_SUCCESS(st)) return st;
    return SendRaw(stackBuf, outLen);
}
