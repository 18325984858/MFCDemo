#include "MainWindow.h"
#include "../Shared/NdarkLog.h"
#include <QApplication>

int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    NDARK_LOG_INFO("ArkQt starting, argc=%d", argc);
    MainWindow w;
    w.resize(1100, 520);
    w.show();
    int rc = app.exec();
    NDARK_LOG_INFO("ArkQt exiting, rc=%d", rc);
    return rc;
}
