# 第三方组件

SplitDirect 本身使用 MIT 许可证（见 [LICENSE](LICENSE)）。它用到、以及打包后的 exe 里附带的第三方组件如下，各自遵循自己的许可证：

| 组件 | 用途 | 许可证 | 源码 |
|---|---|---|---|
| WinDivert 2.2 | 内核网络驱动：抓取、改写数据包 | LGPL-3.0 或 GPL-2.0（二选一） | https://github.com/basil00/WinDivert |
| pydivert | WinDivert 的 Python 接口（附带 WinDivert 二进制文件） | LGPL-3.0 | https://github.com/ffalcinelli/pydivert |
| PySide6（Qt for Python） | 图形界面 | LGPL-3.0 / GPL | https://code.qt.io/cgit/pyside/pyside-setup.git |
| psutil | 查询进程、连接表 | BSD-3-Clause | https://github.com/giampaolo/psutil |
| v2fly/domain-list-community | “常用软件”域名预设的数据来源 | MIT，Copyright (c) 2018-2019 V2Ray | https://github.com/v2fly/domain-list-community |
| PyInstaller | 打包成 exe（不随程序分发，bootloader 带例外条款） | GPL-2.0 with bootloader exception | https://github.com/pyinstaller/pyinstaller |

关于 LGPL 组件：打包后的程序是“文件夹”形式，WinDivert、PySide6/Qt 的动态库都是独立文件，用户可以自行替换成其他兼容版本。上表列出了这些组件的源码地址。
