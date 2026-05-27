#pragma once
#include <afxsock.h>

class CArkDlg;

//
// UDP receiver bound to the configured app IP/port. Validates the shared magic
// header and forwards text payloads to the dialog.
//
class CArkUdp : public CAsyncSocket
{
public:
    explicit CArkUdp(CArkDlg* dlg) : m_dlg(dlg) {}

    bool Start(LPCTSTR bindIp, UINT port);
    bool SendCommand(LPCSTR command);
    bool SendAgentCommand(LPCSTR command);
    virtual void OnReceive(int nErrorCode) override;

private:
    CArkDlg* m_dlg;
};
