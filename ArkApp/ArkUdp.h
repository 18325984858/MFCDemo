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
    bool IsDriverConnected() const { return m_driverConnected; }
    CString GetDriverAddr() const { return m_driverIp; }
    UINT    GetDriverPort() const { return m_driverPort; }
    virtual void OnReceive(int nErrorCode) override;

private:
    CArkDlg* m_dlg;
    bool     m_driverConnected = false;
    CString  m_driverIp;
    UINT     m_driverPort = 0;
};
