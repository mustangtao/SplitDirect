r"""
engine.py —— 分流核心：让指定程序直连，其余流量继续走 VPN

界面（gui.py）只通过这几个接口使用它：
    engine = SplitEngine(on_log=打印日志的函数, on_status=显示状态的函数(状态码, 文字))
        状态码：stopped 已停止 / checking 检查中 / waiting 等待 VPN / running 分流中 / error 出错
    engine.set_apps({"curl.exe", r"c:\...\msedge.exe"})   随时可以改，运行中修改会重置相关程序的旧连接
    engine.set_options(children=True, dns=True, local_domains=["douyin.com"], doh="ali", ipv6=True)
    engine.start()      立即返回；VPN 没连上就等待，连上、重连、IP 变化都会自动跟上
    engine.stop()
    engine.running      用户是否开启了分流
    engine.stats        统计数字（字典）
"""

import ctypes
import http.client
import ipaddress
import json
import queue
import socket
import ssl
import subprocess
import sys
import threading
import time
from collections import namedtuple

import filecmp
import os
import shutil

import psutil
import pydivert


def _use_fixed_driver_folder():
    """把 WinDivert 的 DLL 和驱动复制到 C:\\ProgramData\\SplitDirect\\windivert 后从那里加载。
    驱动加载后会一直占用它的 .sys 文件（程序退出后也是），如果从打包文件夹加载，
    下次打包就删不掉旧文件。放到固定位置后，打包文件夹可以随时清空。"""
    try:
        from pydivert import windivert_dll
        import hashlib
        src_dir = os.path.dirname(windivert_dll.DLL_PATH)
        names = sorted(n for n in os.listdir(src_dir)
                       if n.lower().startswith("windivert") and n.lower().endswith((".dll", ".sys")))
        # 按文件内容算一个版本号：不同版本的驱动放在不同子目录，
        # 避免旧驱动的 .sys 被占用、只换掉了 .dll，造成新 DLL 配旧驱动
        digest = hashlib.sha256()
        for n in names:
            with open(os.path.join(src_dir, n), "rb") as f:
                digest.update(n.encode() + f.read())
        dst_dir = os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                               "SplitDirect", "windivert", digest.hexdigest()[:12])
        os.makedirs(dst_dir, exist_ok=True)
        ok = True
        for n in names:
            src, dst = os.path.join(src_dir, n), os.path.join(dst_dir, n)
            if not os.path.exists(dst) or not filecmp.cmp(src, dst, shallow=False):
                try:
                    shutil.copy2(src, dst)
                except OSError:
                    ok = False        # 复制不完整：不用这个目录，退回默认位置
        new_dll = os.path.join(dst_dir, os.path.basename(windivert_dll.DLL_PATH))
        if ok and os.path.exists(new_dll):
            windivert_dll.DLL_PATH = new_dll   # 第一次调用驱动时才按这个路径加载，所以在这里改有效
    except Exception:
        pass                      # 出任何问题都退回默认位置，不影响使用


_use_fixed_driver_folder()

VPN_KEYWORDS = ("openvpn", "tap-windows", "wintun", "data channel offload")
# 其他常见的隧道 / 虚拟网卡：不会被当成 OpenVPN 网卡，但自动选本地网卡时要排除它们
# （不含 Hyper-V / VMware 等虚拟交换机网卡：用了 Hyper-V 外部交换机时，本机上网走的就是 vEthernet）
TUNNEL_KEYWORDS = ("wireguard", "tailscale", "zerotier", "anyconnect", "cisco", "globalprotect", "pangp",
                   "fortinet", "fortissl", "sangfor", "easyconnect", "openconnect", "softether",
                   "clash", "mihomo", "sing-box")
DNS_REPLY_LIMIT = 1200         # 国内 DNS 的回包超过这么大，改由 VPN 的 DNS 解析（大包要分片，伪造注入不可靠）
UDP_IDLE_SECONDS = 60
CHECK_SECONDS = 5              # 每隔几秒检查一次网卡（VPN 断开、重连、IP 变化）
SLOW_CHECK_SECONDS = 30        # 能收到系统的“网络变化”通知时：变化时立即检查，平时只做低频兜底检查
SOCKET_EVENT_FRESH_SECONDS = 3   # TCP 新连接只认这么多秒内的 SOCKET 事件
FALLBACK_DNS = "223.5.5.5"     # 本地网卡没有 DNS 服务器时用的公共 DNS（阿里）
MAX_PARENT_LEVELS = 10         # 子进程直连：最多往上找几层父进程
MATCH_CACHE_SECONDS = 10       # 一个进程“是否直连”的判断结果记住多久（名单、选项一改就清空）
SLOW_LOOKUP_SECONDS = 0.3      # 新连接排队等判断超过这么久，就在日志里记一条性能记录
CREATE_NO_WINDOW = 0x08000000  # 运行 PowerShell 时不弹出黑色窗口

DEFAULT_OPTIONS = {
    "children": False,     # 名单里程序启动的子进程也直连
    "dns": True,           # 直连程序自己发出的 DNS 查询交给国内 DNS（DoH）解析
    "local_domains": [],   # 这些域名（含子域名）不管哪个程序查询，都交给国内 DNS 解析
    "doh": "ali",          # 国内 DNS 服务：ali = 阿里 DNS，tencent = 腾讯 DNSPod
    "ipv6": True,          # 自动处理 IPv6
    "verbose": False,      # 排查用：走 VPN 的新连接也记到日志里
    "vpn_adapter": "",     # 手动指定的 VPN 网卡名称；空 = 自动识别
    "local_adapter": "",   # 手动指定的本地网卡名称；空 = 自动识别（默认路由跃点最小的）
    "vpn_keywords": [],    # 自动识别时，除了内置关键字以外还算作 VPN 网卡的关键字
}
# 这些选项变化时，要重新识别网卡、重新打开抓包
SESSION_OPTIONS = {"doh", "ipv6", "vpn_adapter", "local_adapter", "vpn_keywords"}

# ======================================================================
# 网卡信息
# ======================================================================

# 一次 PowerShell 调用同时取回：网卡、IPv4/IPv6 地址、默认路由、DNS 服务器
_PS_SCRIPT = (
    "$a = Get-NetAdapter | Where-Object Status -eq 'Up' | "
    "Select-Object ifIndex, Name, InterfaceDescription; "
    "$i = Get-NetIPAddress | Select-Object InterfaceIndex, IPAddress; "
    "$r = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix 0.0.0.0/0 | "
    "Select-Object ifIndex, RouteMetric, NextHop; "
    "$d = Get-DnsClientServerAddress -AddressFamily IPv4 | "
    "Select-Object InterfaceIndex, ServerAddresses; "
    # 经网关的 /32 主机路由：OpenVPN 连接时会加一条“到 VPN 服务器走本地网关”的路由
    "$h = Get-NetRoute -AddressFamily IPv4 | Where-Object { $_.DestinationPrefix -like '*/32' "
    "-and $_.NextHop -ne '0.0.0.0' } | Select-Object ifIndex, DestinationPrefix; "
    "@{adapters=@($a); addresses=@($i); routes=@($r); dns=@($d); hostroutes=@($h)} "
    "| ConvertTo-Json -Compress -Depth 4"
)

Adapters = namedtuple("Adapters", "vpn_ip vpn_index local_ip local_index local_dns vpn_v6 local_v6 tunnel_peers")
Adapters.__new__.__defaults__ = ((),)    # tunnel_peers：VPN 服务器的 IP（隧道本身的加密包来自这些地址）
MAX_TUNNEL_PEERS = 8


def _as_list(x):
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _is_global_v6(addr):
    try:
        return ipaddress.ip_address(str(addr).split("%")[0]).is_global
    except ValueError:
        return False


class AdapterQueryError(Exception):
    """读取网卡信息这件事本身失败了（PowerShell 超时、输出格式不对）——不代表 VPN 断开"""


def query_network():
    """调用一次 PowerShell，返回网卡、地址、默认路由、DNS 的原始数据（字典）。
    读取本身失败时抛出 AdapterQueryError"""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", _PS_SCRIPT],
            capture_output=True, text=True, errors="replace", creationflags=CREATE_NO_WINDOW, timeout=20,
        )
        data = json.loads(result.stdout or "null")
    except subprocess.TimeoutExpired:
        raise AdapterQueryError("读取网卡信息超时")
    except (ValueError, OSError) as e:
        raise AdapterQueryError(f"读取网卡信息失败：{e}")
    err = (result.stderr or "").strip()
    if not isinstance(data, dict):
        raise AdapterQueryError("网卡信息格式异常" + (f"：{err[:200]}" if err else ""))
    # PowerShell 部分命令失败（例如偶尔被拒绝访问）时，输出里可能是空列表：
    # 这是“读取失败”，不能当成“没找到 VPN 网卡”
    if result.returncode != 0 or (err and (not _as_list(data.get("adapters"))
                                           or not _as_list(data.get("addresses"))
                                           or not _as_list(data.get("routes")))):
        raise AdapterQueryError(f"读取网卡信息失败：{err[:200] or f'PowerShell 返回 {result.returncode}'}")
    return data


def find_adapters(options=None):
    """返回 Adapters(...)。options 里可以手动指定网卡（vpn_adapter / local_adapter / vpn_keywords）。
    找不到 VPN 或本地网卡：抛出 RuntimeError；读取网卡信息本身失败：抛出 AdapterQueryError"""
    data = query_network()
    try:
        return parse_adapters(data, options)
    except RuntimeError:
        raise
    except Exception as e:                         # 返回的数据缺字段、类型不对
        raise AdapterQueryError(f"网卡信息格式异常：{e}")


def adapter_rows(data):
    """把原始数据整理成界面用的网卡列表：每项 {index, name, desc, ip, default_route, metric, gateway}
    只列出已连接（Up）的网卡。gateway：默认路由有真实网关（下一跳不是 0.0.0.0）；
    隧道网卡的默认路由一般直接挂在网卡上（下一跳 0.0.0.0）"""
    ip_of = {}
    for a in _as_list(data.get("addresses")):
        ip = str(a["IPAddress"])
        if ":" not in ip and not ip.startswith("169.254."):
            ip_of[a["InterfaceIndex"]] = ip
    metric_of, gateway = {}, set()
    for r in _as_list(data.get("routes")):
        m = r.get("RouteMetric", 0)
        metric_of[r["ifIndex"]] = min(m, metric_of.get(r["ifIndex"], m))
        if str(r.get("NextHop") or "0.0.0.0") != "0.0.0.0":
            gateway.add(r["ifIndex"])
    rows = []
    for ad in _as_list(data.get("adapters")):
        idx = ad["ifIndex"]
        rows.append({"index": idx, "name": str(ad["Name"]), "desc": str(ad["InterfaceDescription"]),
                     "ip": ip_of.get(idx), "default_route": idx in metric_of, "metric": metric_of.get(idx),
                     "gateway": idx in gateway})
    return rows


def is_vpn_adapter(row, extra_keywords=()):
    text = (row["name"] + " " + row["desc"]).lower()
    keywords = list(VPN_KEYWORDS) + [k.strip().lower() for k in extra_keywords if k and k.strip()]
    return any(k in text for k in keywords)


def is_tunnel_adapter(row, extra_keywords=()):
    """VPN 网卡，或者其他隧道 / 虚拟网卡"""
    text = (row["name"] + " " + row["desc"]).lower()
    return is_vpn_adapter(row, extra_keywords) or any(k in text for k in TUNNEL_KEYWORDS)


def parse_adapters(data, options=None):
    options = options or {}
    vpn_name = (options.get("vpn_adapter") or "").strip().lower()
    local_name = (options.get("local_adapter") or "").strip().lower()
    extra = options.get("vpn_keywords") or []

    rows = adapter_rows(data)
    dns_rows = _as_list(data.get("dns"))
    has_v6 = set()    # 有公网 IPv6 地址的接口号
    for a in _as_list(data.get("addresses")):
        ip = str(a["IPAddress"])
        if ":" in ip and _is_global_v6(ip):
            has_v6.add(a["InterfaceIndex"])

    def by_name(name):
        return next((r for r in rows if r["name"].lower() == name), None)

    # ---- VPN 网卡 ----
    if vpn_name:
        vpn = by_name(vpn_name)
        if vpn is None or not vpn["ip"]:
            raise RuntimeError(f"指定的 VPN 网卡“{options.get('vpn_adapter')}”没有连接或还没有 IPv4 地址，"
                               f"请先连上 VPN")
    else:
        vpn = next((r for r in rows if r["ip"] and is_vpn_adapter(r, extra)), None)
        if vpn is None:
            raise RuntimeError("没找到已连接的 VPN 网卡，请先连上 VPN。"
                               "如果已经连上，请在“设置 → 网卡”里手动选择 VPN 网卡")

    # ---- 本地网卡 ----
    if local_name:
        local = by_name(local_name)
        if local is None or not local["ip"]:
            raise RuntimeError(f"指定的本地网卡“{options.get('local_adapter')}”没有连接或没有 IPv4 地址")
        if local["index"] == vpn["index"]:
            raise RuntimeError("VPN 网卡和本地网卡选成了同一个，请在“设置 → 网卡”里修改")
        if is_vpn_adapter(local, extra) and not is_vpn_adapter(vpn, extra):
            raise RuntimeError(f"本地网卡选的“{local['name']}”看起来是 VPN 网卡，VPN 网卡和本地网卡可能选反了，"
                               f"请在“设置 → 网卡”里改回“自动识别”")
    else:
        candidates = [r for r in rows if r["index"] != vpn["index"] and r["ip"] and r["default_route"]
                      and not is_tunnel_adapter(r, extra)]        # 另一个 VPN / 隧道网卡不能当本地网卡
        if not candidates:
            raise RuntimeError("没找到本地网卡的默认路由。"
                               "如果本地网络正常，请在“设置 → 网卡”里手动选择本地网卡")
        # 优先选默认路由有真实网关的（排除名字认不出的隧道网卡）；PPPoE 拨号这类没有网关的也能作为后备
        local = min(candidates, key=lambda r: (not r["gateway"], r["metric"]))

    local_dns = FALLBACK_DNS
    for row in dns_rows:
        if row["InterfaceIndex"] == local["index"]:
            servers = [s for s in _as_list(row.get("ServerAddresses")) if s]
            if servers:
                local_dns = servers[0]
            break

    # VPN 服务器的地址：经本地网卡网关的 /32 主机路由。隧道的加密包从这些地址发来，抓包时排除掉
    peers = []
    for r in _as_list(data.get("hostroutes")):
        if r.get("ifIndex") != local["index"]:
            continue
        ip = str(r.get("DestinationPrefix", "")).split("/")[0]
        try:
            if ipaddress.IPv4Address(ip).is_global and ip not in peers:
                peers.append(ip)
        except ValueError:
            pass
    return Adapters(vpn["ip"], vpn["index"], local["ip"], local["index"],
                    local_dns, vpn["index"] in has_v6, local["index"] in has_v6,
                    tuple(sorted(peers)[:MAX_TUNNEL_PEERS]))


def driver_check():
    """试着打开一次 WinDivert 驱动（过滤条件 false：什么包都不抓），返回 (是否成功, 出错原因)"""
    try:
        w = pydivert.WinDivert("false")
        w.open()
        w.close()
        return True, None
    except Exception as e:
        return False, str(e)


# ======================================================================
# 端口 -> 进程，进程 -> 名字/路径
# ======================================================================

def process_owner(pid, cache):
    """返回进程的 (程序名, 完整路径)，都是小写；cache 是字典，同一个 pid 只查一次"""
    if pid not in cache:
        try:
            p = psutil.Process(pid)
            name = p.name().lower()
            try:
                path = p.exe().lower()
            except psutil.Error:
                path = None
            cache[pid] = (name, path)
        except psutil.Error:
            cache[pid] = (None, None)
    return cache[pid]


# 系统连接表的每一行（GetExtendedTcpTable / GetExtendedUdpTable，带进程号的格式）：
#   (协议, 地址族, 表格类型, 每行字节数, 本机端口在第几个字节, 进程号在第几个字节)
_OWNER_TABLES = [
    ("tcp", 2, 5, 24, 8, 20),      # MIB_TCPROW_OWNER_PID
    ("tcp6", 23, 5, 56, 20, 52),   # MIB_TCP6ROW_OWNER_PID
    ("udp", 2, 1, 12, 4, 8),       # MIB_UDPROW_OWNER_PID
    ("udp6", 23, 1, 28, 20, 24),   # MIB_UDP6ROW_OWNER_PID
]
ERROR_INSUFFICIENT_BUFFER = 122


def parse_owner_rows(buf, proto, row_size, port_at, pid_at, table):
    """解析一张连接表（开头 4 字节是行数），结果写进 table：{(协议, 本机端口): 进程号}"""
    count = int.from_bytes(buf[0:4], "little")
    count = min(count, (len(buf) - 4) // row_size)
    view = memoryview(buf)
    for i in range(count):
        base = 4 + i * row_size
        port = int.from_bytes(view[base + port_at:base + port_at + 2], "big")   # 端口按网络字节序存放
        pid = int.from_bytes(view[base + pid_at:base + pid_at + 4], "little")
        if port and pid:
            table[(proto, port)] = pid


def _read_owner_table(func, family, table_class):
    """调用一次系统接口，返回整张表的字节。ctypes 调用期间会释放 Python 的全局锁，抓包线程不受影响"""
    size = ctypes.c_uint32(0)
    buf = None
    for _ in range(5):                                  # 表格在两次调用之间可能变大，多试几次
        ret = func(buf, ctypes.byref(size), False, family, table_class, 0)
        if ret == 0:
            return bytes(buf) if buf is not None else b"\0\0\0\0"
        if ret != ERROR_INSUFFICIENT_BUFFER:
            raise OSError(f"读取连接表失败（错误 {ret}）")
        buf = ctypes.create_string_buffer(size.value + 4096)
        size = ctypes.c_uint32(len(buf))
    raise OSError("读取连接表失败（连接数一直在变化）")


def port_owner_table():
    """扫描一次系统连接表，返回 {(协议, 本机端口): 进程号}
    协议是 tcp / udp（IPv4）或 tcp6 / udp6（IPv6）。
    直接调用 Windows 接口：比 psutil 快得多，而且调用期间不占用 Python 的全局锁
    （psutil 扫描时整个程序都会停住，连接多的时候一次就要上百毫秒，期间所有包都在排队）"""
    try:
        iphlpapi = ctypes.windll.iphlpapi
        funcs = {"tcp": iphlpapi.GetExtendedTcpTable, "udp": iphlpapi.GetExtendedUdpTable}
    except Exception:
        funcs = None
    if funcs is None:
        return _psutil_owner_table()
    table = {}
    for proto, family, table_class, row_size, port_at, pid_at in _OWNER_TABLES:
        buf = _read_owner_table(funcs[proto[:3]], family, table_class)
        parse_owner_rows(buf, proto, row_size, port_at, pid_at, table)
    return table


def _psutil_owner_table():
    """备用：系统接口用不了时，用 psutil 扫描"""
    table = {}
    for conn in psutil.net_connections(kind="inet"):
        if not conn.laddr or not conn.pid:
            continue
        proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
        if conn.family == socket.AF_INET6:
            proto += "6"
        table[(proto, conn.laddr.port)] = conn.pid
    return table


def entry_matches(apps, name, path):
    """名单里的三种写法：
    程序名     curl.exe                 同名程序都匹配
    完整路径   c:\\...\\msedge.exe        只匹配这个位置的程序
    文件夹     c:\\...\\douyin\\            这个文件夹及子文件夹里的所有程序（以 \\ 结尾）"""
    if name in apps or path in apps:
        return True
    if path:
        for a in apps:
            if a.endswith("\\") and path.startswith(a):
                return True
    return False


def lookup_pid(table, key):
    """先按原协议查；查不到再查另一个协议族（双栈 socket 可能只出现在 IPv6 表里）
    table 的值是进程号"""
    value = table.get(key)
    if value is None:
        proto, port = key
        other = proto[:-1] if proto.endswith("6") else proto + "6"
        value = table.get((other, port))
    return value


# ======================================================================
# SOCKET 层：程序绑定端口、发起连接的那一刻，驱动直接告诉我们是哪个进程
# ======================================================================

EVENT_SOCKET_BIND = 3
EVENT_SOCKET_CONNECT = 4
EVENT_SOCKET_CLOSE = 7
PROTO_NAMES = {6: "tcp", 17: "udp"}


class SocketWatcher:
    """在后台线程里嗅探 SOCKET 层事件，维护 {(协议, 本机端口): (进程号, 时间)}"""

    def __init__(self, on_error, on_loopback_connect=None):
        self.on_error = on_error
        self.on_loopback_connect = on_loopback_connect   # 程序连接本机端口时调用(进程号, 端口)
        self.ports = {}
        self.w = None
        self.ok = False
        self.stopping = False

    def start(self):
        try:
            self.w = pydivert.WinDivert("true", layer=pydivert.Layer.SOCKET,
                                        flags=pydivert.Flag.SNIFF | pydivert.Flag.RECV_ONLY)
            self.w.open()
        except Exception as e:
            self.on_error(f"SOCKET 层不可用（{e}），改用扫描连接表的方式")
            return False
        self.ok = True
        threading.Thread(target=self._loop, daemon=True).start()
        return True

    def stop(self):
        self.stopping = True
        if self.w is not None:
            try:
                pydivert.windivert_dll.WinDivertShutdown(self.w._handle, 1)
            except Exception:
                try:
                    self.w.close()
                except Exception:
                    pass

    def _loop(self):
        w = self.w
        invalid = 0
        try:
            while not self.stopping:
                try:
                    ev = w.recv()
                except Exception:
                    break
                if self.stopping:
                    break
                addr = ev.wd_addr
                # SOCKET 层的事件本来就没有数据内容，不能用“内容为空”判断出错。
                # 驱动出错时接收会立刻返回一个空白结果（层号不是 SOCKET）：连续出现就退出，避免占满 CPU
                if addr.Layer != pydivert.Layer.SOCKET:
                    invalid += 1
                    if invalid >= 100:
                        raise OSError("SOCKET 层连续返回无效事件")
                    time.sleep(0.01)
                    continue
                invalid = 0
                sock = addr.u.Socket
                proto = PROTO_NAMES.get(sock.Protocol)
                if proto is None or not sock.LocalPort:
                    continue
                if addr.IPv6:
                    proto += "6"
                key = (proto, sock.LocalPort)
                if addr.Event == EVENT_SOCKET_CONNECT and addr.Loopback:
                    # 连接的是本机（127.0.0.1）：常见于把流量交给本机代理软件。
                    # 连的是自己开的端口就不算（curl、浏览器等会在本机开一个内部连接给自己用）
                    owner = self.ports.get((proto, sock.RemotePort))
                    if self.on_loopback_connect and sock.RemotePort \
                            and not (owner and owner[0] == sock.ProcessId):
                        self.on_loopback_connect(sock.ProcessId, sock.RemotePort)
                    continue
                if addr.Event in (EVENT_SOCKET_BIND, EVENT_SOCKET_CONNECT):
                    self.ports[key] = (sock.ProcessId, time.time())
                elif addr.Event == EVENT_SOCKET_CLOSE:
                    old = self.ports.get(key)
                    if old and old[0] == sock.ProcessId:
                        self.ports.pop(key, None)
        except Exception as e:
            if not self.stopping:
                self.on_error(f"SOCKET 层监听停止：{e}")
        finally:
            self.ok = False
            try:
                if w.is_open:
                    w.close()
            except Exception:
                pass


# ======================================================================
# DNS：读出查询的域名、判断是否在列表里、构造回包
# ======================================================================

def dns_question(payload):
    """从 DNS 查询里读出 (域名, 类型)，例如 ("www.douyin.com", 1)。不是普通查询就返回 None"""
    try:
        if len(payload) < 17 or payload[2] & 0x80:       # 太短，或者 QR 位是 1（这是回包）
            return None
        if int.from_bytes(payload[4:6], "big") != 1:     # 只处理“一个问题”的普通查询
            return None
        i, labels = 12, []
        while payload[i] != 0:                           # 域名按“长度 + 内容”一段段存放，0 表示结束
            n = payload[i]
            if n & 0xC0:                                 # 查询里不应出现压缩指针
                return None
            labels.append(payload[i + 1:i + 1 + n].decode("ascii", "replace"))
            i += 1 + n
        qtype = int.from_bytes(payload[i + 1:i + 3], "big")
        return ".".join(labels).lower(), qtype
    except IndexError:
        return None


def domain_matches(name, domains):
    """name 是 domains 里某个域名本身或它的子域名，就返回 True。
    例如 domains 里有 douyin.com，则 douyin.com、www.douyin.com、a.b.douyin.com 都匹配"""
    while name:
        if name in domains:
            return True
        dot = name.find(".")
        if dot < 0:
            return False
        name = name[dot + 1:]                            # 去掉最左边一段，再比一次
    return False


def build_udp4(src_ip, dst_ip, src_port, dst_port, payload):
    """构造一个 IPv4 + UDP 包（校验和留空，发送时 pydivert 会重新计算）"""
    total = 28 + len(payload)
    raw = bytearray(total)
    raw[0] = 0x45                                        # 版本 4，头长 5 × 4 = 20 字节
    raw[2:4] = total.to_bytes(2, "big")                  # 总长度
    raw[8] = 64                                          # TTL
    raw[9] = 17                                          # 协议 17 = UDP
    raw[12:16] = socket.inet_aton(src_ip)
    raw[16:20] = socket.inet_aton(dst_ip)
    raw[20:22] = src_port.to_bytes(2, "big")
    raw[22:24] = dst_port.to_bytes(2, "big")
    raw[24:26] = (8 + len(payload)).to_bytes(2, "big")   # UDP 长度 = 8 字节头 + 数据
    raw[28:] = payload
    return raw


def make_query(name, qtype=1):
    """构造一个 DNS 查询（自检用）"""
    q = bytearray(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00")
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    q += b"\x00" + qtype.to_bytes(2, "big") + b"\x00\x01"
    return bytes(q)


# ======================================================================
# DoH：从本地网卡用 HTTPS（443 端口）向国内 DNS 查询
# OpenVPN 的 block-outside-dns 只拦截 53 端口，管不到 443，所以开着它也能用
# ======================================================================

# 服务商 -> (显示名, [(IP, 证书上的域名), ...])。直接连 IP，不需要先解析服务商自己的域名
DOH_PROVIDERS = {
    "ali": ("阿里 DNS", [("223.5.5.5", "dns.alidns.com"), ("223.6.6.6", "dns.alidns.com")]),
    "tencent": ("腾讯 DNSPod", [("1.12.12.12", "doh.pub"), ("120.53.53.53", "doh.pub")]),
}


class _BoundHTTPS(http.client.HTTPSConnection):
    """HTTPS 连接：连指定 IP、从指定的本地 IP 发出、按证书域名校验"""

    def __init__(self, ip, host, local_ip, context):
        super().__init__(host, 443, timeout=3, context=context, source_address=(local_ip, 0))
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout, self.source_address)
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            sock.close()
            raise


class DohClient:
    """后台几个线程，各自保持一条到 DoH 服务器的长连接，按顺序处理查询"""

    MAX_WAIT = 2.0          # 查询在队列里等了这么多秒还没轮到：直接退回 VPN 的 DNS
    FAIL_LIMIT = 3          # 连续失败这么多次：暂停使用一段时间
    PAUSE_SECONDS = 60      # 暂停期间所有查询直接退回 VPN 的 DNS，不再干等超时

    def __init__(self, local_ip, provider, on_answer, on_failed, workers=3):
        self.fails = 0
        self.paused_until = 0.0
        self.local_ip = local_ip
        self.name, self.servers = DOH_PROVIDERS.get(provider, DOH_PROVIDERS["ali"])
        self.on_answer, self.on_failed = on_answer, on_failed
        self.context = ssl.create_default_context()
        self.queue = queue.Queue()
        self.workers = workers
        for _ in range(workers):
            threading.Thread(target=self._worker, daemon=True).start()

    def submit(self, query, ctx):
        if time.time() < self.paused_until:              # 国内 DNS 最近一直失败：直接退回
            self.on_failed(OSError("国内 DNS 暂时不可用"), ctx)
            return
        self.queue.put((query, ctx, time.time()))

    def close(self):
        for _ in range(self.workers):
            self.queue.put(None)

    def _post(self, conn, query):
        conn.request("POST", "/dns-query", body=query, headers={
            "Content-Type": "application/dns-message", "Accept": "application/dns-message"})
        resp = conn.getresponse()
        data = resp.read()
        if resp.status != 200 or len(data) < 12:
            raise OSError(f"HTTP {resp.status}")
        return data

    def query(self, query, state):
        """查一次；state 是线程自己的 {"conn":..., "index":...}，用来复用连接、轮换服务器"""
        last = None
        for _ in range(len(self.servers) + 1):           # 失败就换下一个服务器重试
            if state.get("conn") is None:
                ip, host = self.servers[state.get("index", 0) % len(self.servers)]
                state["conn"] = _BoundHTTPS(ip, host, self.local_ip, self.context)
            try:
                return self._post(state["conn"], query)
            except Exception as e:
                last = e
                try:
                    state["conn"].close()
                except Exception:
                    pass
                state["conn"] = None
                state["index"] = state.get("index", 0) + 1
        raise last

    def test(self):
        """自检：查 www.baidu.com，返回 (是否成功, 用时毫秒, 出错原因)"""
        start = time.perf_counter()
        try:
            self.query(make_query("www.baidu.com"), {})
            return True, (time.perf_counter() - start) * 1000, None
        except Exception as e:
            return False, None, e

    def _worker(self):
        state = {}
        while True:
            item = self.queue.get()
            if item is None:
                if state.get("conn") is not None:
                    state["conn"].close()
                return
            query, ctx, queued_at = item
            if time.time() - queued_at > self.MAX_WAIT or time.time() < self.paused_until:
                self._call(self.on_failed, OSError("国内 DNS 响应太慢"), ctx)
                continue
            try:
                answer = self.query(query, state)
                self.fails = 0
            except Exception as e:
                self.fails += 1
                if self.fails >= self.FAIL_LIMIT:
                    self.paused_until = time.time() + self.PAUSE_SECONDS
                    self.fails = 0
                self._call(self.on_failed, e, ctx)
                continue
            self._call(self.on_answer, answer, ctx)

    @staticmethod
    def _call(func, *args):
        try:
            func(*args)
        except Exception:
            pass                                         # 回调出错不能让 DoH 线程退出


# ======================================================================
# 断开一条 IPv4 TCP 连接（和 TCPView 的“关闭连接”是同一个系统 API）
# ======================================================================

class _MIB_TCPROW(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.c_uint32),
        ("dwLocalAddr", ctypes.c_uint32),
        ("dwLocalPort", ctypes.c_uint32),
        ("dwRemoteAddr", ctypes.c_uint32),
        ("dwRemotePort", ctypes.c_uint32),
    ]


MIB_TCP_STATE_DELETE_TCB = 12  # 状态设成 12 = 让系统删除这条连接


def close_tcp_connection(local_ip, local_port, remote_ip, remote_port):
    """断开一条 IPv4 TCP 连接，成功返回 True（需要管理员权限）"""
    def ip_value(ip):
        # IP 按网络字节序存放在 4 个字节里，再按小端读成整数
        return int.from_bytes(socket.inet_aton(ip), "little")

    row = _MIB_TCPROW(
        MIB_TCP_STATE_DELETE_TCB,
        ip_value(local_ip), socket.htons(local_port),
        ip_value(remote_ip), socket.htons(remote_port),
    )
    return ctypes.windll.iphlpapi.SetTcpEntry(ctypes.byref(row)) == 0


# ======================================================================
# IPv6：构造一个“连接被拒绝”（TCP RST）回包，让程序立刻改用 IPv4
# ======================================================================

def build_rst6_raw(src_addr, dst_addr, src_port, dst_port, seq_num):
    """根据程序发出的 IPv6 SYN 包的地址、端口、序号，构造服务器“拒绝连接”回包的字节"""
    raw = bytearray(60)                                     # 40 字节 IPv6 头 + 20 字节 TCP 头
    raw[0] = 0x60                                           # 版本 6
    raw[4:6] = (20).to_bytes(2, "big")                      # 负载长度 = TCP 头 20 字节
    raw[6] = 6                                              # 下一个头 = TCP
    raw[7] = 64                                             # 跳数限制
    raw[8:24] = socket.inet_pton(socket.AF_INET6, dst_addr)   # 回包来源 = 原来的目标
    raw[24:40] = socket.inet_pton(socket.AF_INET6, src_addr)  # 回包目标 = 程序自己
    raw[40:42] = dst_port.to_bytes(2, "big")
    raw[42:44] = src_port.to_bytes(2, "big")
    raw[48:52] = ((seq_num + 1) & 0xFFFFFFFF).to_bytes(4, "big")  # 确认号 = 对方序号 + 1
    raw[52] = 5 << 4                                        # TCP 头长度 5 × 4 = 20 字节
    raw[53] = 0x14                                          # 标志位 RST + ACK
    return raw


def build_rst6(syn):
    raw = build_rst6_raw(syn.src_addr, syn.dst_addr, syn.src_port, syn.dst_port, syn.tcp.seq_num)
    return pydivert.Packet(raw, interface=syn.interface, direction=pydivert.Direction.INBOUND)


# ======================================================================
# 分流引擎
# ======================================================================

def _new_stats():
    return {"包": 0, "改写": 0, "本地解析": 0, "IPv6拦截": 0,
            "直连连接": 0, "事件命中": 0, "查询": 0, "查询耗时ms": 0.0, "发送失败": 0, "出错": 0}


def _enlarge_queue(w):
    """加大驱动的排队容量（默认约 4MB）：瞬间来一大批包时先排队，而不是直接丢掉"""
    try:
        w.set_param(pydivert.Param.QUEUE_LEN, 8192)
        w.set_param(pydivert.Param.QUEUE_SIZE, 32 * 1024 * 1024)
    except Exception:
        pass


MODIFIED = 2       # _handle 的返回值：包被改写过，发送时要重新计算校验和


def _new_perf(now, stats):
    return {"since": now, "batches": 0, "items": 0, "busy": 0.0, "max_wait": 0.0,
            "scans0": stats["查询"], "scan_ms0": stats["查询耗时ms"]}


class _Session:
    """一次抓包会话，对应一组固定的网卡信息。VPN 重连、IP 变化、选项变化时，关掉旧会话、开一个新会话"""

    def __init__(self, ad, options):
        self.ad = ad
        self.vpn_ip, self.vpn_index = ad.vpn_ip, ad.vpn_index
        self.local_ip, self.local_index = ad.local_ip, ad.local_index
        self.doh = None               # DoH 客户端（打开会话时创建）
        self.vpn_names = set()        # 排查用：已经记过的“走 VPN 解析”的域名
        # IPv6 模式：others = 拦非直连程序；direct = 拦直连程序；None = 不处理
        self.v6_mode = None
        if options["ipv6"]:
            if ad.vpn_v6:
                self.v6_mode = "direct"
            elif ad.local_v6:
                self.v6_mode = "others"
        self.w = None                 # IPv4 抓包句柄
        self.w6 = None                # IPv6 抓包句柄
        self.decisions = {}           # (协议, 本机端口) -> [是否直连, 最后活动时间, (目标IP, 端口), 初始序号, 进程号]
        self.decisions6 = {}          # (协议6, 本机端口) -> [是否拦截, 最后活动时间]
        self.pending = set()          # 正在等后台查询结果的端口
        self.lookup_queue = queue.Queue()
        self.perf = _new_perf(time.time(), {"查询": 0, "查询耗时ms": 0.0})
        self.stopping = False         # True 表示是我们主动关闭的
        self.done = threading.Event()
        self.capture_threads = []


class SplitEngine:
    def __init__(self, on_log=print, on_status=None):
        self.on_log = on_log
        self.on_status = on_status
        self.apps = set()
        self.options = {k: (list(v) if isinstance(v, list) else v) for k, v in DEFAULT_OPTIONS.items()}
        self.running = False          # 用户是否要求分流（VPN 暂时断开时也保持 True）
        self.session = None           # 当前抓包会话；VPN 没连上时为 None
        self.sockets = None           # SOCKET 层事件监听（端口 -> 进程）
        self.stats = _new_stats()
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._waiting_logged = False
        self._last_error_log = 0.0
        self._domains = set()         # 本地解析的域名
        self._generation = 0          # 每次 start() 加 1，用来让旧的监控线程退出
        self._vpn_missing = 0         # 连续几次没找到 VPN 网卡
        self._change_watch = None     # 系统网络变化通知：None 未启动，True 可用，False 不可用
        self._proc_info = {}          # 进程号 -> (程序名, 路径)，界面显示程序状态用
        self._match_cache = {}        # 进程号 -> (时间, (是否直连, 名字))
        self.capturing = False        # “查找软件用到的域名”是否在记录
        self.captured = {}            # 记录到的域名 -> [次数, 第一次出现的时间]

    # ---------------- 对外接口 ----------------

    def set_apps(self, apps):
        """设置直连名单：程序名或完整路径，自动转成小写。
        运行中修改时，名单有变化的程序，其旧连接会被断开，重连后按新名单分流"""
        old_apps, old_children = self.apps, self.options["children"]
        self.apps = {a.lower() for a in apps}
        if old_apps != self.apps:
            self._match_cache = {}
            self._reset_changed(old_apps, old_children)

    def set_options(self, **kw):
        """修改高级选项；运行中修改立即生效"""
        old_apps, old_children = self.apps, self.options["children"]
        changed = {k for k, v in kw.items() if self.options.get(k) != v}
        self.options.update(kw)
        if not changed:
            return
        if "local_domains" in changed:
            self._domains = {d.strip().lower().strip(".") for d in self.options["local_domains"] if d.strip()}
        if "children" in changed:
            self._match_cache = {}
            self._reset_changed(old_apps, old_children)
        if changed & SESSION_OPTIONS and self.running:
            with self._lock:
                self._close_session()     # 关掉当前会话，检查线程马上按新选项重新打开
            self._wake.set()

    def start_capture(self):
        """开始记录走 VPN 解析的域名（“查找软件用到的域名”用）。先清空系统 DNS 缓存，
        否则已经缓存过的域名不会再发查询，就记录不到"""
        self.captured = {}
        try:
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True,
                           creationflags=CREATE_NO_WINDOW, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            pass
        self.capturing = True

    def stop_capture(self):
        self.capturing = False

    def start(self):
        """开始分流。立即返回；检查网卡、等待 VPN、打开驱动都在后台线程里进行"""
        if self.running:
            return
        self.running = True
        # 抓包线程每处理一个包都要拿一次 Python 的全局锁；默认别的线程最多能占着它 5 毫秒，
        # 包多的时候会排队变慢。调短到 1 毫秒，让抓包线程更及时地拿到锁
        sys.setswitchinterval(0.001)
        self._generation += 1                         # 新的一轮：旧的监控线程看到代号变了会自己退出
        self._vpn_missing = 0
        self.stats = _new_stats()
        self._waiting_logged = False
        self._wake.clear()
        self._loopback_warned = set()
        self.sockets = SocketWatcher(on_error=self.on_log, on_loopback_connect=self._on_loopback)
        self.sockets.start()
        self._status("checking", "正在检查网卡……")
        self._start_change_watch()
        threading.Thread(target=self._monitor, args=(self._generation,), daemon=True).start()

    def stop(self):
        if not self.running:
            return
        self.running = False
        self._wake.set()              # 叫醒后台检查线程，让它退出
        with self._lock:
            self._close_session()
        if self.sockets is not None:
            self.sockets.stop()
            self.sockets = None
        self._status("stopped", "未启动")
        self.on_log("已停止，所有流量恢复走 VPN")

    def app_activity(self, matches, recent_seconds=30):
        """名单里每一项的实时状态，给界面显示用（会扫描进程，放在后台线程里调用）。
        返回 {名单项: (正在运行的进程数, 最近 recent_seconds 秒内有流量的直连连接数)}"""
        result = {m: [0, 0] for m in matches}
        cache = {}
        # 进程的名字和路径记下来，下次只查新出现的进程（每次都查全部进程的路径比较费时，
        # 而且会占着 Python 的全局锁，拖慢抓包线程）
        known, alive = self._proc_info, set()
        for p in psutil.process_iter():
            alive.add(p.pid)
            if p.pid not in known:
                known[p.pid] = process_owner(p.pid, {})
            name, path = known[p.pid]
            for m in matches:
                if entry_matches({m}, name, path):
                    result[m][0] += 1
        for pid in [pid for pid in known if pid not in alive]:
            known.pop(pid, None)
        s = self.session
        if s is not None:
            now = time.time()
            pids = {}
            for entry in s.decisions.copy().values():    # 先复制：抓包线程随时会往里加新连接
                if entry[0] and len(entry) > 4 and now - entry[1] < recent_seconds:
                    pids[entry[4]] = pids.get(entry[4], 0) + 1
            children = self.options["children"]
            for pid, count in pids.items():
                for m in matches:
                    if self._match(pid, cache, {m}, children)[0]:
                        result[m][1] += count
        return {m: tuple(v) for m, v in result.items()}

    # ---------------- 判断一个进程是否直连 ----------------

    def _match(self, pid, cache, apps=None, children=None):
        """返回 (是否直连, 显示用的名字)。apps / children 不传就用当前设置。
        用当前设置判断时，结果按进程记住一会儿：同一个程序同时开几百个连接，只需要查一次进程链"""
        if apps is None and children is None and pid is not None:
            hit = self._match_cache.get(pid)
            now = time.time()
            if hit is not None and now - hit[0] < MATCH_CACHE_SECONDS:
                return hit[1]
            result = self._match_uncached(pid, cache, self.apps, self.options["children"])
            if len(self._match_cache) > 5000:
                self._match_cache.clear()
            self._match_cache[pid] = (now, result)
            return result
        return self._match_uncached(pid, cache, apps, children)

    def _match_uncached(self, pid, cache, apps=None, children=None):
        apps = self.apps if apps is None else apps
        children = self.options["children"] if children is None else children
        if pid is None:
            return False, None
        name, path = process_owner(pid, cache)
        if entry_matches(apps, name, path):
            return True, path or name
        if children:
            try:
                for level, parent in enumerate(psutil.Process(pid).parents()):
                    if level >= MAX_PARENT_LEVELS:
                        break
                    pname, ppath = process_owner(parent.pid, cache)
                    if entry_matches(apps, pname, ppath):
                        return True, f"{path or name}（由 {pname} 启动）"
            except psutil.Error:
                pass
        return False, path or name

    def _on_loopback(self, pid, port):
        """直连程序连接本机端口 → 很可能是把流量交给了本机代理（v2rayN、Clash 等），提醒一次"""
        try:
            direct, label = self._match(pid, {})
            if not direct or (pid, port) in self._loopback_warned:
                return
            self._loopback_warned.add((pid, port))
            self.on_log(f"[注意] {label} 正在连接本机端口 127.0.0.1:{port}。如果这是代理软件（v2rayN、Clash 等）"
                        f"的端口，这部分流量会由代理软件发出，不会直连")
        except Exception:
            pass

    def _status(self, state, text):
        if self.on_status:
            self.on_status(state, text)

    def _start_change_watch(self):
        """让 Windows 在 IP 地址或路由变化时通知我们（VPN 连上、断开、换网络都会触发），
        这样平时不用频繁运行 PowerShell。两个监听线程一直在后台等通知，只启动一次"""
        if self._change_watch is not None:
            return
        self._change_watch = False
        try:
            funcs = [ctypes.windll.iphlpapi.NotifyAddrChange, ctypes.windll.iphlpapi.NotifyRouteChange]
        except Exception:
            return                                   # 用不了：退回每 5 秒检查一次
        self._change_watch = True
        for func in funcs:
            threading.Thread(target=self._watch_changes, args=(func,), daemon=True).start()

    def _watch_changes(self, func):
        fails = 0
        while True:
            try:
                ret = func(None, None)               # 两个参数都传空：一直等到下一次变化才返回
            except Exception:
                ret = -1
            if ret == 0:
                fails = 0
                time.sleep(1)                        # 一次变化往往连着好几个通知：等它们发完再检查
                if self.running:
                    self._wake.set()
            else:
                fails += 1
                if fails >= 3:
                    self._change_watch = False       # 一直失败：退回每 5 秒检查一次
                    return
                time.sleep(5)

    def _monitor(self, generation):
        while self.running and generation == self._generation:
            failed = False
            try:
                self._check_adapters()
            except Exception as e:
                failed = True
                self._status("error", f"出错：{e}（{CHECK_SECONDS} 秒后重试）")
                self._error(e)
            # 有网络变化通知、上一次检查也成功时，低频兜底即可；否则保持每 5 秒检查
            slow = self._change_watch and not failed
            self._wake.wait(SLOW_CHECK_SECONDS if slow else CHECK_SECONDS)
            self._wake.clear()

    def _check_adapters(self):
        try:
            found = find_adapters(self.options)
        except RuntimeError as e:
            found, reason = None, str(e)
            self._vpn_missing += 1
            if self.session is not None and self._vpn_missing < 2:
                self._wake.set()                      # 正在分流时第一次没找到：先不拆，马上再查一次
                return
        except AdapterQueryError as e:
            # 只是这一次没读到网卡信息：保持当前状态，下一轮再查（不要因此中断分流）
            if self.session is None:
                self._status("waiting", f"等待 VPN 连接……（{e}）")
            self._error(e)
            return

        if found is not None:
            self._vpn_missing = 0
        with self._lock:
            if not self.running:
                return
            s = self.session
            if s is not None and found == s.ad and not s.done.is_set():
                return                                  # 一切照旧

            if s is not None:                           # VPN 断了、IP 变了、或抓包意外停止
                self._close_session()

            if found is None:
                if not self._waiting_logged:
                    self.on_log(f"{reason}。连上后会自动开始分流")
                    self._waiting_logged = True
                self._status("waiting", "等待 VPN 连接……")
                return

            self._open_session(found)
            self._waiting_logged = False

    def _open_session(self, ad):
        s = _Session(ad, self.options)
        # 发往本地网卡的包里，VPN 隧道自己的加密包占了绝大多数（VPN 下载多快，它就有多少），
        # 它们和直连程序无关：直接在驱动里排除，不进 Python，VPN 速度不受影响
        skip = "".join(f" and ip.SrcAddr != {ip}" for ip in ad.tunnel_peers)
        filter4 = (
            f"ip and not loopback and ("
            f"(outbound and ip.SrcAddr == {ad.vpn_ip}) or "
            f"(inbound and ip.DstAddr == {ad.local_ip}{skip}))"
        )
        # IPv6 只抓发出去的：TCP 只抓建立连接的第一个包，UDP 全抓
        filter6 = "ipv6 and outbound and not loopback and ((tcp and tcp.Syn and not tcp.Ack) or udp)"
        try:
            s.w = pydivert.WinDivert(filter4)
            s.w.open()
            if s.v6_mode:
                s.w6 = pydivert.WinDivert(filter6)
                s.w6.open()
            for w in (s.w, s.w6):
                if w is not None:
                    _enlarge_queue(w)
        except Exception as e:
            for w in (s.w, s.w6):
                try:
                    if w is not None and w.is_open:
                        w.close()
                except Exception:
                    pass
            raise RuntimeError(f"打开 WinDivert 驱动失败：{e}")

        self.session = s
        s.perf = _new_perf(time.time(), self.stats)
        threading.Thread(target=self._lookup_worker, args=(s,), daemon=True).start()
        s.capture_threads = [threading.Thread(target=self._loop, args=(s, s.w, self._handle, s.decisions),
                                              daemon=True)]
        if s.w6 is not None:
            s.capture_threads.append(threading.Thread(
                target=self._loop, args=(s, s.w6, self._handle6, s.decisions6), daemon=True))
        for t in s.capture_threads:
            t.start()

        self.on_log(f"开始分流：VPN 网卡 {ad.vpn_ip}（接口 {ad.vpn_index}），"
                    f"本地网卡 {ad.local_ip}（接口 {ad.local_index}）"
                    + (f"，VPN 服务器 {'、'.join(ad.tunnel_peers)}" if ad.tunnel_peers else ""))
        s.doh = DohClient(ad.local_ip, self.options["doh"], self._doh_answer, self._doh_failed)
        threading.Thread(target=self._check_dns, args=(s,), daemon=True).start()
        parts = []
        if self.options["dns"]:
            parts.append("直连程序的 DNS 查询")
        if self._domains:
            parts.append(f"{len(self._domains)} 个指定域名")
        if parts:
            self.on_log(f"{'、'.join(parts)} 交给 {s.doh.name} 解析（DNS over HTTPS，从本地网卡发出）")
        if s.v6_mode == "others":
            self.on_log("IPv6：VPN 不支持、本地网络支持 → 拦截非直连程序的 IPv6，让它们走 VPN 的 IPv4")
        elif s.v6_mode == "direct":
            self.on_log("IPv6：VPN 支持 → 拦截直连程序的 IPv6，让它们走能直连的 IPv4")
        self._status("running", f"运行中    VPN 网卡 {ad.vpn_ip}    本地网卡 {ad.local_ip}")
        # 名单里的程序如果之前就开着，断开它们走 VPN 的旧连接，让它们重连后走直连
        self._reset_in_background(s, lambda pid, cache: self._match(pid, cache)[0])

    def _check_dns(self, s):
        ok, ms, err = s.doh.test()
        if s.stopping:
            return
        if ok:
            self.on_log(f"国内 DNS 自检通过：{s.doh.name}（DNS over HTTPS）用时 {ms:.0f}ms")
        else:
            self.on_log(
                f"[注意] 国内 DNS 自检失败：从本地网卡连不上 {s.doh.name}（{err}）。"
                f"需要本地解析的域名会暂时改由 VPN 的 DNS 解析，可以在设置里换一个国内 DNS 服务再试")

    def _close_session(self):
        s = self.session
        if s is None:
            return
        self.session = None
        s.stopping = True
        if s.doh is not None:
            s.doh.close()
        for w in (s.w, s.w6):
            if w is None:
                continue
            try:
                # 让驱动停止接收新包；已经排队的包会被取完，然后 recv 返回空包，抓包循环退出
                pydivert.windivert_dll.WinDivertShutdown(w._handle, 1)  # 1 = 只停止接收
            except Exception:
                try:
                    w.close()
                except Exception:
                    pass
        for t in s.capture_threads:
            if t is not threading.current_thread():
                t.join(timeout=2)

    # ---------------- 旧连接重置 ----------------

    def _reset_changed(self, old_apps, old_children):
        """名单或子进程选项变化后，断开“直连与否”发生变化的程序的旧连接"""
        s = self.session
        if s is None:
            return

        def changed(pid, cache):
            before = self._match(pid, cache, old_apps, old_children)[0]
            after = self._match(pid, cache)[0]
            return before != after
        self._reset_in_background(s, changed)

    def _reset_in_background(self, s, match):
        threading.Thread(target=self._reset_connections, args=(s, match), daemon=True).start()

    def _reset_connections(self, s, match):
        """断开 VPN 网卡上、match(进程号, cache) 为真的进程的 TCP 连接；程序会自动重连"""
        try:
            closed = {}
            failed = 0
            cache = {}
            for conn in psutil.net_connections(kind="tcp4"):
                if not conn.raddr or not conn.pid or conn.laddr.ip != s.vpn_ip:
                    continue
                if conn.status not in (psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT):
                    continue
                if not match(conn.pid, cache):
                    continue
                if close_tcp_connection(conn.laddr.ip, conn.laddr.port,
                                        conn.raddr.ip, conn.raddr.port):
                    name, path = process_owner(conn.pid, cache)
                    prog = path or name
                    closed[prog] = closed.get(prog, 0) + 1
                else:
                    failed += 1
            for prog, n in closed.items():
                self.on_log(f"已断开 {prog} 的 {n} 个旧连接，它会自动重连并按名单分流")
            if failed:
                self.on_log(f"有 {failed} 个旧连接没能断开，可以手动重启对应程序")
        except Exception as e:
            self._error(f"断开旧连接失败：{e}")

    # ---------------- 公共小工具 ----------------

    def _error(self, text):
        self.stats["出错"] += 1
        now = time.time()
        if now - self._last_error_log > 2:
            self._last_error_log = now
            self.on_log(f"处理出错：{text}")

    def _send(self, s, w, packet, recalc=True):
        """recalc=False：包没改过，不用重新计算校验和（绝大多数包都是这样，省一次计算）"""
        try:
            if w.send(packet, recalculate_checksum=recalc) == 0:
                self.stats["发送失败"] += 1
        except Exception as e:
            if not s.stopping:
                self.stats["发送失败"] += 1
                self._error(f"发送失败：{e}")

    @staticmethod
    def _proto(packet):
        if packet.tcp is not None:
            return "tcp"
        if packet.udp is not None:
            return "udp"
        return None

    # ---------------- IPv4：改写 ----------------

    def _rewrite_outbound(self, s, packet, entry):
        entry[1] = time.time()
        if not entry[0]:
            return
        packet.src_addr = s.local_ip               # 源 IP 换成本地网卡 IP
        packet.interface = (s.local_index, 0)      # 从本地网卡发出
        self.stats["改写"] += 1

    def _handle(self, s, packet):
        """处理一个 IPv4 包。返回 True：已交给后台线程，抓包循环不要再发送它；
        MODIFIED：改写过，发送时要重新算校验和；False：原样放行"""
        proto = self._proto(packet)
        if proto is None:
            return False

        now = time.time()
        if packet.is_outbound:
            # 查询的域名在“本地解析”列表里：不管哪个程序发的，都交给国内 DNS
            if proto == "udp" and packet.dst_port == 53 \
                    and (self._domains or self.options["verbose"] or self.capturing) \
                    and self._try_local_dns(s, packet, force=False):
                return True
            key = (proto, packet.src_port)
            entry = s.decisions.get(key)
            new_tcp = proto == "tcp" and packet.tcp.syn and not packet.tcp.ack
            if (new_tcp and entry is not None and len(entry) > 3 and now - entry[1] < 10
                    and entry[2] == (packet.dst_addr, packet.dst_port) and entry[3] == packet.tcp.seq_num):
                # 同一个连接重发的 SYN（目标和初始序号都相同）：沿用第一次的判断，避免一半直连一半走 VPN。
                # 端口被别的连接复用时，初始序号是新的随机数，会重新判断
                new_tcp = False
            stale_udp = proto == "udp" and (entry is None or now - entry[1] > UDP_IDLE_SECONDS)
            if new_tcp or stale_udp or key in s.pending:
                s.pending.add(key)
                s.lookup_queue.put(("v4", key, packet, now))
                return True
            if entry is not None:
                if entry[0] and self._try_local_dns(s, packet, force=True):
                    return True                    # 直连程序自己的 DNS 查询：交给国内 DNS
                self._rewrite_outbound(s, packet, entry)
                return MODIFIED if entry[0] else False
        else:
            key = (proto, packet.dst_port)
            entry = s.decisions.get(key)
            if entry is not None and entry[0]:
                if proto == "tcp" and len(entry) > 2 and entry[2][0] != packet.src_addr:
                    return False                       # 端口撞上了别的连接：不改
                entry[1] = now
                packet.dst_addr = s.vpn_ip                 # 目标 IP 换回 VPN 网卡 IP
                packet.interface = (s.vpn_index, 0)        # 当作从 VPN 网卡收到
                self.stats["改写"] += 1
                return MODIFIED
        return False

    # ---------------- 本地解析：把 DNS 查询交给国内 DNS（DoH） ----------------

    def _try_local_dns(self, s, packet, force):
        """packet 是发往 VPN DNS 的查询时，交给 DoH 并返回 True（原包不再发送）。
        force=True：直连程序自己的查询，任何域名都交给国内 DNS；
        force=False：只有域名在列表里才交给国内 DNS"""
        if s.doh is None or packet.udp is None or packet.dst_port != 53:
            return False
        if force and not self.options["dns"]:
            return False
        payload = packet.payload
        q = dns_question(payload) if payload else None
        if q is None:
            return False
        if not force and not domain_matches(q[0], self._domains):
            if self.capturing:                        # 查找域名：记下这个走 VPN 解析的域名
                item = self.captured.setdefault(q[0], [0, time.time()])
                item[0] += 1
            if self.options["verbose"] and q[0] not in s.vpn_names:   # 排查用：每个域名只记一次
                s.vpn_names.add(q[0])
                self.on_log(f"[DNS 走VPN] {q[0]}")
            return False
        self.stats["本地解析"] += 1
        if self.options["verbose"]:
            self.on_log(f"[本地解析] {q[0]}" + ("（直连程序）" if force else "（在域名列表里）"))
        s.doh.submit(bytes(payload), (s, packet, q[0]))
        return True

    def _doh_answer(self, answer, ctx):
        """DoH 查到了：伪造一个“VPN DNS 发回来的”回包，交还给程序"""
        s, query, name = ctx
        if s.stopping:
            return
        try:
            payload = bytes(query.payload)
            # 查询里没带 EDNS（附加记录数为 0）的程序只收 512 字节以内的 UDP 回包
            limit = DNS_REPLY_LIMIT if payload[10:12] != b"\x00\x00" else 512
            if len(answer) > limit:
                self._doh_failed(OSError(f"回包 {len(answer)} 字节太大"), ctx)
                return
            answer = payload[:2] + answer[2:]                  # 回包编号必须和查询一致
            raw = build_udp4(query.dst_addr, query.src_addr, 53, query.src_port, answer)
            reply = pydivert.Packet(raw, interface=(s.vpn_index, 0), direction=pydivert.Direction.INBOUND)
            self._send(s, s.w, reply)
        except Exception as e:                                 # 出任何问题：原查询交给 VPN 的 DNS，不让程序干等
            self._doh_failed(e, ctx)

    def _doh_failed(self, err, ctx):
        """DoH 查不到：原查询照常发给 VPN 的 DNS，至少还能解析出结果"""
        s, query, name = ctx
        if s.stopping:
            return
        self._error(f"国内 DNS 查询 {name} 失败（{err}），这次改由 VPN 的 DNS 解析")
        self._send(s, s.w, query, recalc=False)

    # ---------------- IPv6：拦截 ----------------

    def _apply6(self, s, packet, block):
        """IPv6 包：要拦截就丢弃（TCP 还要回一个拒绝包）；否则放行"""
        if not block:
            self._send(s, s.w6, packet, recalc=False)
            return
        self.stats["IPv6拦截"] += 1
        if packet.tcp is not None:
            try:
                self._send(s, s.w6, build_rst6(packet))
            except Exception as e:
                self._error(f"构造 IPv6 拒绝包失败：{e}")
        # 原包不发送 = 丢弃

    def _handle6(self, s, packet):
        """处理一个 IPv6 出站包。返回 True 表示已经处理（发送或丢弃），抓包循环不要再发送它"""
        proto = self._proto(packet)
        if proto is None or not _is_global_v6(packet.dst_addr):
            return False                      # 局域网、链路本地地址：原样放行
        key = (proto + "6", packet.src_port)
        entry = s.decisions6.get(key)
        now = time.time()
        if proto == "tcp" or entry is None or now - entry[1] > UDP_IDLE_SECONDS or key in s.pending:
            s.pending.add(key)
            s.lookup_queue.put(("v6", key, packet, now))
            return True
        entry[1] = now
        self._apply6(s, packet, entry[0])
        return True

    # ---------------- 后台查询线程 ----------------

    def _lookup_worker(self, s):
        """查询线程：新连接的包都在这里等待判断。它一旦退出，所有新连接都会卡住，
        所以每一批都包在 try 里：出任何意外，这一批包原样放行，线程继续工作"""
        try:
            while True:
                item = s.lookup_queue.get()
                if item is None:          # 收到结束信号
                    return
                batch = [item]
                time.sleep(0.003)
                while not s.lookup_queue.empty():
                    item = s.lookup_queue.get()
                    if item is None:
                        s.lookup_queue.put(None)  # 先处理完这一批，下一轮再退出
                        break
                    batch.append(item)
                try:
                    self._process_batch(s, batch)
                except Exception as e:
                    self._error(f"处理新连接出错：{e}")
                    for family, key, packet, _ in batch:    # 原样放行，至少不会卡住
                        s.pending.discard(key)
                        self._send(s, s.w if family == "v4" else s.w6, packet, recalc=False)
        finally:
            if not s.stopping:                           # 不是正常关闭：让检查线程重启会话
                s.done.set()
                self._wake.set()

    def _process_batch(self, s, batch):
        start = time.time()
        table = self._resolve_owners([item[1] for item in batch])
        cache = {}
        for family, key, packet, _ in batch:
            try:
                if family == "v4":
                    self._decide_v4(s, key, packet, table, cache)
                else:
                    self._decide_v6(s, key, packet, table, cache)
            except Exception as e:
                self._error(e)
                s.pending.discard(key)
                self._send(s, s.w if family == "v4" else s.w6, packet, recalc=False)
        self._record_perf(s, batch, start)

    def _record_perf(self, s, batch, start):
        """记下新连接排队等判断的时间；5 秒内最长的超过 0.3 秒，就在日志里写一条性能记录，方便排查卡顿"""
        now = time.time()
        p = s.perf
        p["batches"] += 1
        p["items"] += len(batch)
        p["busy"] += now - start
        p["max_wait"] = max(p["max_wait"], max(now - item[3] for item in batch))
        if now - p["since"] < 5:
            return
        scans = self.stats["查询"] - p["scans0"]
        scan_ms = self.stats["查询耗时ms"] - p["scan_ms0"]
        if p["max_wait"] > SLOW_LOOKUP_SECONDS:
            self.on_log(
                f"[性能] 最近 {now - p['since']:.0f} 秒：新连接 {p['items']} 个，分 {p['batches']} 批判断，"
                f"排队最长 {p['max_wait'] * 1000:.0f}ms，判断共用时 {p['busy'] * 1000:.0f}ms，"
                f"扫描连接表 {scans} 次" + (f"（平均 {scan_ms / scans:.0f}ms）" if scans else "")
                + f"，当前还有 {s.lookup_queue.qsize()} 个在排队")
        s.perf = _new_perf(now, self.stats)

    def _resolve_owners(self, keys):
        """为一批端口找到所属进程，返回 {(协议, 端口): 进程号}
        顺序：① SOCKET 层事件表里“新鲜”的记录 ② 稍等 10 毫秒再查一次（事件可能比数据包晚到）
              ③ 扫描系统连接表"""
        keys = set(keys)             # 同一个端口的多个包会一起排队（UDP 连发很常见），只查一次
        sockets = self.sockets
        if sockets is not None and sockets.ok:
            found = self._fresh_owners(sockets.ports, keys)
            if len(found) < len(keys):
                time.sleep(0.01)
                found = self._fresh_owners(sockets.ports, keys)
            if len(found) == len(keys):
                self.stats["事件命中"] += len(keys)
                return found
        else:
            found = {}

        start = time.perf_counter()
        try:
            table = port_owner_table()
        except Exception as e:
            self._error(f"查连接表失败：{e}")
            table = {}
        self.stats["查询"] += 1
        self.stats["查询耗时ms"] += (time.perf_counter() - start) * 1000
        table.update(found)          # 新鲜的事件记录最准确，覆盖扫描结果
        return table

    @staticmethod
    def _fresh_owners(ports, keys):
        """从事件表里取出可信的记录。
        TCP 新连接：只认 3 秒内的事件——发起连接的事件总是紧挨着第一个包；
        更旧的记录可能是端口被回收前的上一个程序留下的。
        UDP：一个 socket 可以用很久，事件记录不限时间。"""
        now = time.time()
        found = {}
        for key in keys:
            proto, port = key
            other = (proto[:-1] if proto.endswith("6") else proto + "6", port)
            for k in (key, other):
                value = ports.get(k)
                if value is None:
                    continue
                pid, ts = value
                if proto.startswith("tcp") and now - ts > SOCKET_EVENT_FRESH_SECONDS:
                    continue
                found[key] = pid
                break
        return found

    def _decide_v4(self, s, key, packet, table, cache):
        entry = s.decisions.get(key)
        if entry is None or key in s.pending:
            pid = lookup_pid(table, key)
            direct, label = self._match(pid, cache)
            isn = packet.tcp.seq_num if packet.tcp is not None and packet.tcp.syn else None
            entry = [direct, time.time(), (packet.dst_addr, packet.dst_port), isn, pid]
            if direct:
                self.stats["直连连接"] += 1
            s.decisions[key] = entry
            s.pending.discard(key)
            if direct:
                self.on_log(f"[直连] {label}  {key[0]}  本机端口 {key[1]} -> "
                            f"{packet.dst_addr}:{packet.dst_port}")
            elif self.options["verbose"]:
                self.on_log(f"[走VPN] {label or '未知进程'}  {key[0]}  本机端口 {key[1]} -> "
                            f"{packet.dst_addr}:{packet.dst_port}")
        if entry[0] and self._try_local_dns(s, packet, force=True):
            return                                 # 直连程序自己的 DNS 查询：交给国内 DNS
        self._rewrite_outbound(s, packet, entry)
        self._send(s, s.w, packet, recalc=bool(entry[0]))

    def _decide_v6(self, s, key, packet, table, cache):
        entry = s.decisions6.get(key)
        if entry is None or key in s.pending or key[0] == "tcp6":
            first = entry is None or key in s.pending
            pid = lookup_pid(table, key)
            direct, label = self._match(pid, cache)
            block = (s.v6_mode == "others" and not direct) or (s.v6_mode == "direct" and direct)
            entry = [block, time.time()]
            s.decisions6[key] = entry
            s.pending.discard(key)
            if block and direct and first:
                self.on_log(f"[IPv6 拦截] {label}  让它改用 IPv4 直连")
        self._apply6(s, packet, entry[0])

    # ---------------- 抓包循环（IPv4、IPv6 共用） ----------------

    def _loop(self, s, w, handler, decisions):
        count = 0
        reason = None
        try:
            while True:
                try:
                    packet = w.recv()
                except Exception:
                    if s.stopping:
                        break
                    raise
                if len(packet.raw) == 0:      # 关闭后驱动返回空包
                    break
                self.stats["包"] += 1
                try:
                    handled = handler(s, packet)
                except Exception as e:
                    self._error(e)
                    handled = MODIFIED                # 出错时可能改了一半：按改过处理，重新算校验和
                if handled is not True:
                    self._send(s, w, packet, recalc=handled == MODIFIED)
                count += 1
                if count % 20000 == 0:
                    now = time.time()
                    for k in [k for k, v in decisions.copy().items() if now - v[1] > 300]:
                        decisions.pop(k, None)
        except Exception as e:
            reason = f"抓包意外停止：{e}"
        finally:
            is_main = w is s.w
            if is_main:
                s.lookup_queue.put(None)
                time.sleep(0.05)      # 给后台线程一点时间把手上的包发完
            try:
                if w.is_open:
                    w.close()
            except Exception:
                pass
            if is_main or reason:
                s.done.set()
            if reason and not s.stopping:
                self.on_log(reason + "，马上自动重试")
                self._wake.set()      # 让检查线程立刻重新打开
