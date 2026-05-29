/*++
    NetLink.cpp --- Skeleton entry that exercises the kernel C++ toolchain
    (_purecall stub, placement new, vtable dispatch) so that link-time
    failures surface early. Real link factories will be added here in the
    next migration step.
--*/

#include "NetLink.h"
#include "NetLinkApi.h"
#include "../Shared/NdarkLog.h"

namespace {

// Minimal concrete derivation: exercises virtual dispatch without doing any
// real I/O. No global constructors -- placement-newed on demand into .bss.
class HealthCheckLink final : public NetLinkBase
{
public:
    HealthCheckLink() { SetName("healthcheck"); }

    NTSTATUS Connect() override                          { return STATUS_SUCCESS; }
    NTSTATUS Heartbeat() override                        { return STATUS_SUCCESS; }
    NTSTATUS RecvPacket(PVOID, ULONG, PULONG outLen) override
    {
        if (outLen) *outLen = 0;
        return STATUS_SUCCESS;
    }
    BOOLEAN VerifyPacket(const VOID*, ULONG) const override { return TRUE; }
    NTSTATUS BuildPacket(const VOID* payload, ULONG payLen,
                         PVOID outBuf, ULONG cap, PULONG outLen) const override
    {
        if (payLen > cap) return STATUS_BUFFER_TOO_SMALL;
        if (payload && payLen && outBuf) RtlCopyMemory(outBuf, payload, payLen);
        if (outLen) *outLen = payLen;
        return STATUS_SUCCESS;
    }

protected:
    NTSTATUS SendRaw(const VOID*, ULONG) override { return STATUS_SUCCESS; }
};

// Static storage in .bss; no global constructor runs.
alignas(HealthCheckLink) static unsigned char g_HealthStorage[sizeof(HealthCheckLink)];

} // namespace

extern "C" NTSTATUS NetLinkRuntimeSelfTest(VOID)
{
    // Construct in place; no operator new is involved.
    HealthCheckLink* p = new (g_HealthStorage) HealthCheckLink();
    if (!p) return STATUS_UNSUCCESSFUL;

    // Exercise vtable dispatch.
    NTSTATUS st = p->Connect();
    if (NT_SUCCESS(st)) {
        UCHAR  buf[8] = {0};
        ULONG  outLen = 0;
        st = p->BuildPacket("x", 1, buf, sizeof(buf), &outLen);
        if (NT_SUCCESS(st) && outLen != 1) st = STATUS_UNSUCCESSFUL;
    }

    // Explicit destruction; storage is static so no operator delete is used.
    p->~HealthCheckLink();
    NDARK_LOG_INFO("NetLink C++ runtime self-test result=0x%08X", st);
    return st;
}
