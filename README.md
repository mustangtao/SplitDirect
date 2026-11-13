# SplitDirect

**中文** | [English](README.en.md)

让 **指定的 Windows 程序直连**，其余流量继续走 **OpenVPN 全局隧道**。

OpenVPN 只能按“目标 IP”分流，不能按“程序”分流。SplitDirect 补上这一块：比如 VPN 开着全局，但让抖音、网易云音乐、某个浏览器走本地网络，其他程序照常走 VPN。

> 需要 Windows 10 / 11（64 位）和管理员权限。目前针对 OpenVPN（TAP-Windows、Wintun、DCO 网卡），其他 VPN 可以在设置里手动指定网卡试用。

## 功能

- **按程序直连**：三种写法——程序名（`curl.exe`，所有同名程序）、完整路径（只匹配这一个位置）、文件夹（文件夹里所有程序，适合 `抖音\8.7.0\...` 这类带版本号的多进程软件）
- **子进程也直连**：名单里的程序启动的其他程序也直连（启动器打开的游戏、`cmd` 里运行的 `curl`/`git` 等）
- **国内 DNS**：直连程序的 DNS 查询改由阿里 / 腾讯 DNS（DNS over HTTPS，从本地网卡发出）解析，拿到离你最近的服务器。即使 OpenVPN 开了 `block-outside-dns` 也能用
- **常用软件域名预设**：腾讯、字节跳动、阿里、B 站等 28 组，勾选后这些域名交给国内 DNS（数据来自 [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)，每周自动检查更新）；也可以用“查找软件用到的域名”自己抓
- **自动跟随 VPN**：VPN 断开、重连、换 IP、换 WiFi 都会自动跟上；网络变化后大约 1 秒内重新检查
- **IPv6 处理**：VPN 不支持 IPv6 时，拦截非直连程序的 IPv6，防止它们绕过 VPN
- **连接列表**：实时看每个连接属于哪个程序、走直连还是 VPN、为什么，可以筛选、搜索、复制
- **一键自检**：逐项检查管理员权限、驱动、网卡、国内 DNS、系统代理、名单里每个程序的状态，有问题会说明怎么处理
- **其他**：托盘运行、开机自启、暂停 30 分钟、规则导出/导入、深色模式、诊断信息导出

## 下载和使用

1. 在 [Releases](../../releases) 下载压缩包，解压到任意位置（不要放在会被清理的临时目录）。压缩包由 GitHub Actions 自动打包，旁边的 `.sha256` 文件可以用 `Get-FileHash 压缩包名.zip` 核对
2. 用 OpenVPN GUI 连上 VPN（全局模式）
3. 双击 `SplitDirect.exe`（会请求管理员权限），点“添加程序”选择要直连的软件，再点“开始分流”
4. 不确定有没有生效：点底部的“连接”看每个连接走了直连还是 VPN，或者点“自检”，也可以看每个程序右边显示的直连连接数

关闭窗口不会退出，程序会缩到托盘；右键托盘图标可以暂停或退出。退出后所有流量恢复走 VPN。

## 常见问题

**加了程序，但它还是走 VPN？**
- 先看“连接”里这个程序的连接是直连还是走 VPN，“原因”一栏会说明；再看“自检”。最常见的原因是系统代理开着（v2rayN、Clash 等设置的）：浏览器会把流量交给代理软件，而不是自己直连
- 名单里的程序如果之前已经打开，SplitDirect 会断开它的旧连接让它重连；个别程序不会自动重连，重启一下即可

**直连了，但抖音 / QQ 之类的很慢或打不开？**
这类软件用 Windows 系统 DNS 解析域名，查询会经 VPN 到海外 DNS，拿到海外节点。到“设置 → DNS”里勾选对应的常用软件（添加程序时也会提示）。列表里没有的软件，用“查找软件用到的域名”抓出来，加到自定义域名。

**浏览器打开国内网站选的是海外节点？**
Chrome、Edge 等直连浏览器自己发的 DNS 查询会自动交给国内 DNS。但如果浏览器开了“安全 DNS”并指定了服务商（例如 Cloudflare），SplitDirect 管不到，建议改成“使用当前服务提供商”。

**命令行下载（curl、git、pip）想直连？**
添加 `cmd.exe`（PowerShell 是 `powershell.exe` / `pwsh.exe`），并开启“子进程也直连”。

**用的不是 OpenVPN？**
在“设置 → 网卡”里手动选择 VPN 网卡和本地网卡。注意 AnyConnect、GlobalProtect 等公司 VPN 往往自带防火墙规则，可能直接拦截本地直连。

## 工作原理

```
程序 ──(源地址 = VPN 网卡 IP)──> WinDivert 抓包
                                   │
            属于直连名单的程序？───┤
             是：源地址改成本地网卡 IP，从本地网卡发出
             否：原样放行，照常走 VPN
回包 ──(目标 = 本地网卡 IP)──> 目标改回 VPN 网卡 IP，交还给程序
```

- 用 [WinDivert](https://github.com/basil00/WinDivert) 在网络层改写数据包，程序本身无感知
- 判断数据包属于哪个程序：优先用 WinDivert 的 SOCKET 层事件（程序绑定端口、发起连接时驱动直接告知进程号），查不到再扫描系统连接表
- 直连程序发给 VPN DNS 的查询被拦下，改用 DNS over HTTPS（443 端口）从本地网卡查询国内 DNS，再伪造成 VPN DNS 的回包交给程序
- 驱动文件会复制到 `C:\ProgramData\SplitDirect\windivert\` 后加载，所以程序文件夹可以随时删除或覆盖更新

设置保存在 `%APPDATA%\SplitDirect\`，日志按天保存在其中的 `logs` 文件夹（保留 7 天）。

## 从源码运行 / 打包

需要 Python 3.10 以上（64 位）。

```bat
pip install -r requirements.txt
python gui.py            :: 需要在管理员命令行里运行
build.bat                :: 打包成 dist\SplitDirect\SplitDirect.exe
```

| 文件 | 内容 |
|---|---|
| `engine.py` | 分流核心：网卡识别、抓包改写、DNS、IPv6、进程识别 |
| `gui.py` | 图形界面（PySide6） |
| `preset_updater.py` | 常用软件域名的解析、联网更新 |
| `tools/ci_smoke.py` | 界面冒烟测试（GitHub Actions 打包前运行） |
| `domain_presets.py` | 程序自带的域名预设（由 `tools/gen_presets.py` 生成） |

## 注意

- SplitDirect 需要管理员权限并加载网络驱动，部分安全软件可能会拦截或报警
- 请遵守你所在网络（学校、公司）以及 VPN 服务的使用规定；有些机构的 VPN 要求所有流量都经过隧道
- 本软件按“原样”提供，不对使用后果承担责任（见 MIT 许可证）

## 许可证

[MIT](LICENSE)。用到的第三方组件及其许可证见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
