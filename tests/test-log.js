// Network ARK — 测试脚本记录文件
// 约定:以后所有测试脚本文件统一存放在本目录 (tests/) 下。

const testLog = [
  {
    id: 1,
    date: "2026-05-30",
    name: "build-verify",
    description: "验证 build_all.cmd 能成功生成 NetDrv.sys 与 ArkQt.exe",
    status: "pending",
    scriptPath: "tests/build-verify.js"
  },
  {
    id: 2,
    date: "2026-05-30",
    name: "netlink-refactor-phase1",
    description: "NetLink 重构第 1 阶段:QtApp 新增 NetLinkBase 抽象基类,UdpLink/TcpChannel 改为继承之并实现 6 契约方法(doConnect/heartbeat/recvPacket/sendPacket/verifyPacket/buildPacket);NetDrv 新增 KernelCxx.cpp + NetLink.h/cpp + NetLinkApi.h 局部 C++ 岛屿骨架,placement new + vtable 自检在 DriverEntry 调用,NetDrv.sys 编译通过。",
    status: "passed",
    scriptPath: "tests/netlink-refactor-phase1.js"
  }
];

module.exports = testLog;
