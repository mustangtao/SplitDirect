"""
gui.py —— SplitDirect 图形界面（PySide6）

运行：
    pip install pyside6 pydivert psutil
    python gui.py               （需要管理员权限）
    python gui.py --autostart   （开机自启用：不显示窗口，直接进托盘）

界面结构：
    主窗口：状态卡片（开始/停止/暂停）、提示条、直连程序列表（含实时状态）、底部的“自检”“设置”“日志”
    设置窗口：开机自启、外观、规则导出/导入、子进程、DNS、网卡、IPv6、排查选项
    自检窗口：逐项检查权限、驱动、网卡、国内 DNS、系统代理、名单里的程序
    日志窗口：实时日志、统计、打开日志文件夹、导出诊断信息
"""

import copy
import ctypes
import datetime
import json
import logging
import logging.handlers
import os
import platform
import subprocess
import sys
import threading
import time
import zipfile

import psutil
from PySide6.QtCore import (
    QAbstractAnimation, QEasingCurve, QFileInfo, QObject, QPropertyAnimation, QSize, Qt, QTimer, Signal,
)
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QPainter, QPalette, QPen, QPixmap
from PySide6.QtNetwork import QLocalServer, QLocalSocket
from PySide6.QtWidgets import (
    QAbstractButton, QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog,
    QDialogButtonBox, QFileDialog, QFileIconProvider, QFrame, QHBoxLayout,
    QGridLayout, QInputDialog, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMenu,
    QMessageBox, QPlainTextEdit, QPushButton, QRadioButton, QScrollArea, QStyle,
    QSystemTrayIcon, QVBoxLayout, QWidget,
)

import domain_presets
import preset_updater
from engine import (
    DEFAULT_OPTIONS, AdapterQueryError, DohClient, SplitEngine, adapter_rows, domain_matches,
    driver_check, is_vpn_adapter, parse_adapters, query_network,
)

# 界面自己的选项（引擎不需要知道）
GUI_DEFAULTS = dict(DEFAULT_OPTIONS, domain_presets=[], theme="system")
THEME_CHOICES = [("system", "跟随系统"), ("light", "浅色"), ("dark", "深色")]

# 两级后缀：base_domain 用来把 img.example.com.cn 归到 example.com.cn
SECOND_LEVEL = {"com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
                "com.hk", "com.tw", "co.uk", "co.jp", "com.au", "com.sg"}


# 程序路径或名字里出现这些词，就认为它属于对应的预设（全部小写）
APP_KEYWORDS = {
    "tencent": ["\\tencent\\", "\\qq.exe", "weixin", "wechat", "qqmusic", "qqlive", "wegame",
                "wemeet", "wxwork", "qqbrowser", "qqnt"],
    "bytedance": ["bytedance", "douyin", "feishu", "lark", "jianying", "toutiao", "xigua"],
    "alibaba": ["alibaba", "aliyun", "taobao", "alipay", "dingtalk", "youku", "amap", "aliwangwang", "quark"],
    "baidu": ["baidu"],
    "netease": ["netease", "cloudmusic", "163music", "neteasemusic", "youdao"],
    "bilibili": ["bilibili", "哔哩"],
    "kuaishou": ["kuaishou", "kwai"],
    "xiaohongshu": ["xiaohongshu", "xhs"],
    "sina": ["weibo", "\\sina"],
    "zhihu": ["zhihu"],
    "jd": ["jingdong", "\\jd\\", "jdapp"],
    "meituan": ["meituan"],
    "pinduoduo": ["pinduoduo", "\\pdd"],
    "iqiyi": ["iqiyi", "qiyi"],
    "mihoyo": ["mihoyo", "hoyoverse", "genshin", "yuanshen", "starrail"],
    "huawei": ["huawei"],
    "xiaomi": ["xiaomi"],
    "douyu_huya": ["douyu", "huya"],
    "kugou_kuwo": ["kugou", "kuwo"],
    "wps": ["\\wps", "kingsoft"],
    "csdn": ["csdn"],
    "douban": ["douban"],
    "ctrip": ["ctrip"],
    "didi": ["didi"],
    "ximalaya": ["ximalaya"],
    "xunlei": ["xunlei", "thunder"],
    "qihoo360": ["qihoo", "\\360", "360se", "360chrome"],
    "cctv": ["cctv", "cbox"],
}


def presets_for_app(match, title=""):
    """直连名单里的一项属于哪些预设，例如 c:\\...\\tencent\\weixin\\weixin.exe -> {"tencent"}"""
    text = ("\\" + match + " " + (title or "")).lower()   # 前面补一个 \，只写程序名（qq.exe）时也能匹配
    return {key for key, words in APP_KEYWORDS.items() if any(w in text for w in words)}


def base_domain(name):
    """主域名：img.wxgateway.com -> wxgateway.com；a.b.example.com.cn -> example.com.cn"""
    parts = name.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

APP_NAME = "SplitDirect"
APP_VERSION = "0.9.4"
CONFIG_DIR = os.path.join(os.environ.get("APPDATA", "."), APP_NAME)
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
LOG_DIR = os.path.join(CONFIG_DIR, "logs")
PRESETS_FILE = os.path.join(CONFIG_DIR, "domain_presets.json")   # 联网更新后的预设
PRESETS_CHECK_DAYS = 7                                            # 每隔几天自动检查一次
SERVER_NAME = "SplitDirect-single-instance"
CREATE_NO_WINDOW = 0x08000000

DOH_CHOICES = [("ali", "阿里 DNS"), ("tencent", "腾讯 DNSPod")]


RULES_FORMAT = "splitdirect-rules"


def rules_to_dict(entries, options):
    """导出的规则：直连名单、勾选的常用软件、自定义域名、两个和名单相关的选项"""
    return {
        "format": RULES_FORMAT,
        "version": 1,
        "app_version": APP_VERSION,
        "exported": datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "apps": [{"match": e["match"], "enabled": bool(e["enabled"])} for e in entries],
        "domain_presets": list(options.get("domain_presets", [])),
        "local_domains": list(options.get("local_domains", [])),
        "options": {"children": bool(options.get("children")), "dns": bool(options.get("dns"))},
    }


def parse_rules(data):
    """检查并整理导入的规则文件内容；格式不对抛出 ValueError"""
    if not isinstance(data, dict) or data.get("format") != RULES_FORMAT:
        raise ValueError("这不是 SplitDirect 导出的规则文件")
    apps = []
    for a in data.get("apps") or []:
        if isinstance(a, str):
            a = {"match": a}
        if isinstance(a, dict) and isinstance(a.get("match"), str) and a["match"].strip():
            apps.append({"match": a["match"].strip().lower(), "enabled": bool(a.get("enabled", True))})
    presets = [k for k in data.get("domain_presets") or [] if isinstance(k, str)]
    domains = clean_domains("\n".join(d for d in data.get("local_domains") or [] if isinstance(d, str)))
    raw_opts = data.get("options") if isinstance(data.get("options"), dict) else {}
    opts = {k: raw_opts[k] for k in ("children", "dns") if isinstance(raw_opts.get(k), bool)}
    if not apps and not presets and not domains:
        raise ValueError("规则文件里没有任何程序或域名")
    return {"apps": apps, "domain_presets": presets, "local_domains": domains, "options": opts}


def merge_unique(old, new):
    return list(old) + [x for x in new if x not in old]


def clean_domains(text):
    """把用户输入的文字整理成域名列表：每行一个，去掉 http://、*.、路径和空行，转小写、去重"""
    result = []
    for line in text.replace(",", "\n").replace("，", "\n").splitlines():
        d = line.split("#")[0].strip().lower()
        for prefix in ("https://", "http://", "*."):
            if d.startswith(prefix):
                d = d[len(prefix):]
        d = d.split("/")[0].strip(".")
        if d and "." in d and d not in result:
            result.append(d)
    return result


# 颜色：只用一个强调色（绿），其余是灰阶
GREEN = "#2e9d4f"
STATUS = {
    # 状态码: (圆点颜色, 大标题)
    "running": (GREEN, "正在分流"),
    "checking": ("#e0a200", "正在检查网卡"),
    "waiting": ("#e0a200", "等待 VPN 连接"),
    "stopped": ("#9aa0a6", "未开启"),
    "error": ("#d64545", "出现问题"),
    "paused": ("#5b8def", "已暂停"),
}
PAUSE_MINUTES = 30

# 两套配色：样式表、开关等自绘控件都从这里取颜色
THEMES = {
    "light": dict(
        bg="#f5f6f8", card="#ffffff", border="#e3e5e8", text="#1f2328", sub="#6b7280", faint="#8a9099",
        banner_bg="#fff7e0", banner_border="#f1d58a", btn_bg="#ffffff", btn_hover="#f0f2f4",
        btn_border="#d0d4d9", disabled="#a0a4a8", link="#4b5563", accent_hover="#eef6f0",
        line="#eef0f2", row_hover="#f6f8f7", input_bg="#ffffff", primary_hover="#278a44",
        switch_off="#c9cdd2", pal_light="#ffffff", pal_dark="#a0a4a8", pal_shadow="#7a7f86"),
    "dark": dict(
        bg="#1e1f22", card="#2b2d31", border="#3a3d42", text="#e6e7e9", sub="#a0a4aa", faint="#8a8f96",
        banner_bg="#3a3220", banner_border="#6b5a2a", btn_bg="#2b2d31", btn_hover="#34373c",
        btn_border="#4a4d52", disabled="#6b6f75", link="#c3c6cb", accent_hover="#23352a",
        line="#34373c", row_hover="#30333a", input_bg="#232428", primary_hover="#36b05c",
        switch_off="#55595f", pal_light="#34373c", pal_dark="#151618", pal_shadow="#000000"),
}
COLORS = dict(THEMES["light"])      # 当前使用的配色（切换主题时整体替换）


def build_style(c):
    return f"""
QWidget {{ font-family: "Microsoft YaHei UI", "Microsoft YaHei"; font-size: 10pt; color: {c['text']}; }}
QWidget#root, QDialog {{ background: {c['bg']}; }}
QFrame#card {{ background: {c['card']}; border: 1px solid {c['border']}; border-radius: 10px; }}
QLabel#title {{ font-size: 15pt; font-weight: 600; }}
QLabel#sub, QLabel#hint {{ color: {c['sub']}; }}
QLabel#hint {{ font-size: 9pt; }}
QLabel#section {{ font-weight: 600; margin-top: 6px; }}
QLabel#appname {{ font-weight: 600; }}
QLabel#apppath {{ color: {c['faint']}; font-size: 9pt; }}
QLabel#empty {{ color: {c['faint']}; padding: 24px; }}
QFrame#banner {{ background: {c['banner_bg']}; border: 1px solid {c['banner_border']}; border-radius: 8px; }}
QPushButton {{ border: 1px solid {c['btn_border']}; border-radius: 6px; padding: 6px 14px; background: {c['btn_bg']}; }}
QPushButton:hover {{ background: {c['btn_hover']}; }}
QPushButton:disabled {{ color: {c['disabled']}; }}
QPushButton#primary {{ background: {GREEN}; color: white; border: none; font-weight: 600; padding: 9px 24px; }}
QPushButton#primary:hover {{ background: {c['primary_hover']}; }}
QPushButton#stop {{ font-weight: 600; padding: 9px 24px; }}
QPushButton#link {{ border: none; background: transparent; color: {c['link']}; padding: 4px 8px; }}
QPushButton#link:hover {{ color: {GREEN}; }}
QPushButton#accent {{ color: {GREEN}; border: 1px solid {GREEN}; border-radius: 6px;
                     padding: 5px 14px; background: {c['btn_bg']}; font-weight: 600; }}
QPushButton#accent:hover {{ background: {c['accent_hover']}; }}
QPushButton#accent:disabled {{ color: {c['disabled']}; border-color: {c['btn_border']}; }}
QPushButton::menu-indicator {{ width: 0; }}
QListWidget {{ border: none; background: transparent; outline: none; }}
QListWidget::item {{ border-bottom: 1px solid {c['line']}; }}
QListWidget::item:selected, QListWidget::item:hover {{ background: {c['row_hover']}; color: {c['text']}; }}
QListWidget#panel {{ background: {c['input_bg']}; border: 1px solid {c['border']}; border-radius: 8px; }}
QLineEdit, QComboBox {{ border: 1px solid {c['btn_border']}; border-radius: 6px; padding: 5px 8px; background: {c['input_bg']}; }}
QPlainTextEdit {{ border: 1px solid {c['border']}; border-radius: 8px; background: {c['input_bg']};
                  font-family: Consolas, "Microsoft YaHei UI"; font-size: 9pt; }}
QScrollArea {{ background: transparent; }}
QMenu {{ background: {c['card']}; border: 1px solid {c['border']}; padding: 4px; }}
QMenu::item {{ padding: 6px 22px; border-radius: 4px; }}
QMenu::item:selected {{ background: {c['accent_hover']}; color: {c['text']}; }}
QToolTip {{ background: {c['card']}; color: {c['text']}; border: 1px solid {c['border']}; }}
"""


STYLE = build_style(COLORS)


# ======================================================================
# 配置、日志文件、管理员权限、单实例、开机自启、系统代理
# ======================================================================

def load_config():
    cfg = {}
    for path in (CONFIG_FILE, CONFIG_FILE + ".bak"):     # 主文件坏了就用上一次的备份
        try:
            with open(path, encoding="utf-8") as f:
                cfg = json.load(f)
            if isinstance(cfg, dict):
                break
        except (OSError, ValueError):
            pass
        cfg = {}
    if not isinstance(cfg.get("direct_apps"), list):
        cfg["direct_apps"] = []
    if not isinstance(cfg.get("options"), dict):
        cfg["options"] = {}
    if not isinstance(cfg.get("running"), bool):
        cfg["running"] = False
    if not isinstance(cfg.get("presets_checked"), (int, float)) or isinstance(cfg.get("presets_checked"), bool):
        cfg["presets_checked"] = 0
    # 旧版本的名单是字符串列表，新版本每一项是 {"match": ..., "enabled": ...}
    apps = []
    for a in cfg.get("direct_apps", []):
        if isinstance(a, str):
            apps.append({"match": a.lower(), "enabled": True})
        elif isinstance(a, dict) and a.get("match"):
            apps.append({"match": a["match"].lower(), "enabled": bool(a.get("enabled", True))})
    cfg["direct_apps"] = apps
    return cfg


def save_config(cfg):
    """先写临时文件再替换：写到一半断电或崩溃，原来的配置也不会损坏；替换前保留一份备份"""
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        tmp = CONFIG_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        if os.path.exists(CONFIG_FILE):
            try:
                os.replace(CONFIG_FILE, CONFIG_FILE + ".bak")
            except OSError:
                pass
        os.replace(tmp, CONFIG_FILE)
    except OSError as e:
        logging.getLogger(APP_NAME).error(f"保存配置失败：{e}")


def setup_file_log():
    """日志文件：按天分文件，保留 7 天"""
    os.makedirs(LOG_DIR, exist_ok=True)
    logger = logging.getLogger(APP_NAME)
    if logger.handlers:                              # 已经设置过了
        return logger
    logger.setLevel(logging.INFO)
    handler = logging.handlers.TimedRotatingFileHandler(
        os.path.join(LOG_DIR, "splitdirect.log"), when="midnight", backupCount=7, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s  %(message)s"))
    logger.addHandler(handler)
    return logger


def ensure_admin():
    """不是管理员就用管理员身份重新启动自己，然后退出当前进程"""
    if ctypes.windll.shell32.IsUserAnAdmin():
        return
    if getattr(sys, "frozen", False):
        # 打包成 exe 后：sys.executable 就是 SplitDirect.exe 本身，不需要再传脚本路径
        args = sys.argv[1:]
        workdir = os.path.dirname(sys.executable)
    else:
        script = os.path.abspath(sys.argv[0])      # 管理员进程的当前目录会变，所以用绝对路径
        args = [script] + sys.argv[1:]
        workdir = os.path.dirname(script)
    params = " ".join(f'"{a}"' for a in args)
    ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, workdir, 1)
    if ret <= 32:  # 返回值不大于 32 表示失败（被系统拦截或用户点了"否"）
        ctypes.windll.user32.MessageBoxW(
            None,
            "没能自动获取管理员权限。\n\n请这样运行：\n"
            "开始菜单搜索 cmd → 右键“以管理员身份运行” → 进入程序所在文件夹 → python gui.py",
            APP_NAME, 0x30)
    sys.exit(0)


def tell_running_instance():
    """如果已经有一个 SplitDirect 在运行，叫它显示窗口，返回 True"""
    sock = QLocalSocket()
    sock.connectToServer(SERVER_NAME)
    if not sock.waitForConnected(300):
        return False
    sock.write(b"show")
    sock.flush()
    sock.waitForBytesWritten(300)
    sock.disconnectFromServer()
    return True


def _run_hidden(cmd, timeout=15):
    """运行外部命令（不弹黑窗口）。超时或出错时返回一个“失败”的结果，而不是抛出异常卡住界面"""
    try:
        return subprocess.run(cmd, capture_output=True, text=True, errors="replace",
                              creationflags=CREATE_NO_WINDOW, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError) as e:
        return subprocess.CompletedProcess(cmd, 1, "", f"运行 {cmd[0]} 失败：{e}")


def launch_command():
    """开机时要执行的命令"""
    if getattr(sys, "frozen", False):
        return f'"{sys.executable}" --autostart'
    # 用 pythonw.exe 运行脚本，开机时不会弹出黑色窗口
    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    if not os.path.exists(pythonw):
        pythonw = sys.executable
    return f'"{pythonw}" "{os.path.abspath(sys.argv[0])}" --autostart'


def desktop_user():
    """当前登录桌面的用户（explorer.exe 的所有者），例如 DESKTOP-XXX\\86177"""
    for p in psutil.process_iter(["name", "username"]):
        if (p.info["name"] or "").lower() == "explorer.exe" and p.info["username"]:
            return p.info["username"]
    return None


def desktop_folder():
    """登录用户自己的桌面文件夹（管理员保护下，程序的“我的桌面”是另一个系统账户的）"""
    user = desktop_user()
    if user:
        path = os.path.join(os.environ.get("SystemDrive", "C:") + "\\Users",
                            user.split("\\")[-1], "Desktop")
        if os.path.isdir(path):
            return path
    return os.path.expanduser("~")


_sid_cache = {}


def desktop_user_sid():
    """登录桌面的用户的 SID（只查一次，之后用缓存）。
    管理员保护下本程序以另一个系统账户运行，读“当前用户”的注册表读到的是那个账户的，
    所以要按登录用户的 SID 去 HKEY_USERS 下读取"""
    if _sid_cache.get("sid"):
        return _sid_cache["sid"]
    if time.time() - _sid_cache.get("tried", 0) < 30:    # 刚查过没查到：30 秒内不重复查
        return None
    _sid_cache["tried"] = time.time()
    user = desktop_user()                                # 开机自启时桌面可能还没加载完，会是 None
    if user:
        r = _run_hidden(["powershell", "-NoProfile", "-Command",
                         f"(New-Object System.Security.Principal.NTAccount('{user}'))"
                         f".Translate([System.Security.Principal.SecurityIdentifier]).Value"])
        if r.stdout.strip().startswith("S-"):
            _sid_cache["sid"] = r.stdout.strip()            # 只缓存查到的结果
    return _sid_cache.get("sid")


def system_dark_mode():
    """Windows 的“应用模式”是否为深色"""
    import winreg
    path = r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
    sid = desktop_user_sid()
    for root, sub in ((winreg.HKEY_USERS, f"{sid}\\{path}" if sid else None),
                      (winreg.HKEY_CURRENT_USER, path)):
        if not sub:
            continue
        try:
            key = winreg.OpenKey(root, sub)
            value = winreg.QueryValueEx(key, "AppsUseLightTheme")[0]
            winreg.CloseKey(key)
            return value == 0
        except OSError:
            continue
    return False


def set_dark_titlebar(widget, dark):
    """让窗口标题栏也变深色（Windows 10 1809 以后支持；20 是新编号，19 是旧版本系统的编号）"""
    try:
        hwnd = int(widget.winId())
        value = ctypes.c_int(1 if dark else 0)
        for attr in (20, 19):
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(value), 4) == 0:
                break
    except Exception:
        pass


def theme_palette(dark):
    """Fusion 风格下控件（勾选框、滚动条、下拉框、弹窗）用的颜色。
    浅色、深色都把每个颜色明确写出来：不能用 Qt 的默认配色，因为它也会参考系统的深浅设置，
    从深色切回浅色时，勾选框等控件会残留深色"""
    c = THEMES["dark" if dark else "light"]
    pal = QPalette()
    for role, color in [
        (QPalette.Window, c["bg"]), (QPalette.WindowText, c["text"]), (QPalette.Base, c["input_bg"]),
        (QPalette.AlternateBase, c["bg"]), (QPalette.Text, c["text"]), (QPalette.Button, c["btn_bg"]),
        (QPalette.ButtonText, c["text"]), (QPalette.BrightText, "#ffffff"),
        (QPalette.ToolTipBase, c["card"]), (QPalette.ToolTipText, c["text"]),
        (QPalette.PlaceholderText, c["faint"]), (QPalette.Highlight, GREEN), (QPalette.HighlightedText, "#ffffff"),
        (QPalette.Link, GREEN), (QPalette.Light, c["pal_light"]), (QPalette.Midlight, c["border"]),
        (QPalette.Mid, c["btn_border"]), (QPalette.Dark, c["pal_dark"]), (QPalette.Shadow, c["pal_shadow"]),
    ]:
        pal.setColor(role, QColor(color))                       # 不指定分组 = 激活、非激活、禁用三种状态都设置
    for role in (QPalette.WindowText, QPalette.Text, QPalette.ButtonText):
        pal.setColor(QPalette.Disabled, role, QColor(c["disabled"]))
    return pal


def apply_theme(dark):
    """切换整个程序的配色：样式表、控件颜色、所有窗口的标题栏"""
    COLORS.clear()
    COLORS.update(THEMES["dark" if dark else "light"])
    app = QApplication.instance()
    app.setPalette(theme_palette(dark))
    app.setStyleSheet(build_style(COLORS))
    for w in app.topLevelWidgets():
        if w.isWindow():
            set_dark_titlebar(w, dark)
            w.update()


def system_proxy():
    """读取登录用户的系统代理设置，开启时返回代理地址，否则返回 None"""
    import winreg
    sid = desktop_user_sid()
    if not sid:
        return None
    try:
        key = winreg.OpenKey(winreg.HKEY_USERS,
                             sid + r"\Software\Microsoft\Windows\CurrentVersion\Internet Settings")
        enabled = winreg.QueryValueEx(key, "ProxyEnable")[0]
        server = winreg.QueryValueEx(key, "ProxyServer")[0] if enabled else ""
        winreg.CloseKey(key)
    except OSError:
        return None
    return (server or None) if enabled else None


def autostart_enabled():
    return _run_hidden(["schtasks", "/Query", "/TN", APP_NAME]).returncode == 0


def set_autostart(enable):
    if enable:
        cmd = ["schtasks", "/Create", "/TN", APP_NAME, "/TR", launch_command(),
               "/SC", "ONLOGON", "/RL", "HIGHEST", "/F"]
        user = desktop_user()
        if user:
            cmd += ["/RU", user, "/IT"]   # 在这个用户登录时、在他的桌面上运行
    else:
        cmd = ["schtasks", "/Delete", "/TN", APP_NAME, "/F"]
    r = _run_hidden(cmd)
    if r.returncode != 0:
        raise RuntimeError((r.stderr or r.stdout).strip())


# ======================================================================
# 程序的友好名字和图标
# ======================================================================

def file_description(path):
    """读取 exe 文件属性里的“文件说明”，例如 msedge.exe -> Microsoft Edge；读不到返回 None"""
    try:
        ver = ctypes.windll.version
        size = ver.GetFileVersionInfoSizeW(path, None)
        if not size:
            return None
        buf = ctypes.create_string_buffer(size)
        if not ver.GetFileVersionInfoW(path, 0, size, buf):
            return None
        ptr = ctypes.c_void_p()
        length = ctypes.c_uint()
        # 先查文件用的语言和代码页，再按它去读 FileDescription
        if not ver.VerQueryValueW(buf, "\\VarFileInfo\\Translation", ctypes.byref(ptr), ctypes.byref(length)):
            return None
        lang, codepage = ctypes.cast(ptr, ctypes.POINTER(ctypes.c_uint16 * 2)).contents
        key = f"\\StringFileInfo\\{lang:04x}{codepage:04x}\\FileDescription"
        if not ver.VerQueryValueW(buf, key, ctypes.byref(ptr), ctypes.byref(length)) or length.value <= 1:
            return None
        text = ctypes.wstring_at(ptr.value, length.value - 1).strip()
        return text or None
    except Exception:
        return None


def find_running_exe(name):
    """按程序名找一个正在运行的同名进程，返回它的完整路径"""
    for p in psutil.process_iter(["name", "exe"]):
        if (p.info["name"] or "").lower() == name and p.info["exe"]:
            return p.info["exe"]
    return None


_icon_provider = None


def exe_icon(path):
    global _icon_provider
    if _icon_provider is None:
        _icon_provider = QFileIconProvider()
    if path and os.path.exists(path):
        return _icon_provider.icon(QFileInfo(path))
    return QApplication.style().standardIcon(QStyle.SP_FileIcon)


def describe_entry(match):
    """名单里的一项 -> (图标, 名字, 说明)"""
    if match.endswith("\\"):                              # 文件夹
        folder = match.rstrip("\\")
        base = os.path.basename(folder)
        # 文件夹里如果有同名 exe（例如 douyin\douyin.exe），用它的图标和名字
        main_exe = os.path.join(folder, base + ".exe")
        if os.path.exists(main_exe):
            title = file_description(main_exe) or base
            return exe_icon(main_exe), title, f"{match}  ·  文件夹里的所有程序"
        icon = QApplication.style().standardIcon(QStyle.SP_DirIcon)
        return icon, base, f"{match}  ·  文件夹里的所有程序"
    if "\\" not in match:                                 # 程序名
        path = find_running_exe(match)
        title = (file_description(path) if path else None) or match
        return exe_icon(path), title, f"{match}  ·  所有同名程序"
    title = (file_description(match) if os.path.exists(match) else None) or os.path.basename(match)
    return exe_icon(match), title, match                  # 完整路径


# ======================================================================
# 小部件：状态图标、开关、自动省略的文字
# ======================================================================

def status_icon(state):
    """画一个彩色圆形图标，中间是白色的“分叉”符号，表示分流"""
    pix = QPixmap(64, 64)
    pix.fill(Qt.transparent)
    p = QPainter(pix)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor(STATUS.get(state, STATUS["stopped"])[0]))
    p.drawEllipse(2, 2, 60, 60)
    pen = QPen(QColor("white"), 6, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    p.setPen(pen)
    p.drawLine(32, 50, 32, 32)     # 下面一根
    p.drawLine(32, 32, 19, 16)     # 分出左边
    p.drawLine(32, 32, 45, 16)     # 分出右边
    p.end()
    return QIcon(pix)


class Switch(QAbstractButton):
    """开关：绿色 = 开，灰色 = 关"""

    def __init__(self, checked=True, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setChecked(checked)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(38, 22)

    def sizeHint(self):
        return QSize(38, 22)

    def paintEvent(self, event):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(GREEN if self.isChecked() else COLORS["switch_off"]))
        p.drawRoundedRect(0, 0, 38, 22, 11, 11)
        p.setBrush(QColor("white"))
        p.drawEllipse(18 if self.isChecked() else 2, 2, 18, 18)
        p.end()


class SmoothScrollArea(QScrollArea):
    """滚动区域：鼠标滚轮带动画平滑滚动（默认是一格一跳）。
    连续滚动时目标位置累加，动画从当前位置接着走，不会卡顿或回弹"""

    STEP = 120          # 滚轮转一格滚动的像素
    DURATION = 280      # 动画时长（毫秒）

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._target = None
        self._anim = QPropertyAnimation(self.verticalScrollBar(), b"value", self)
        self._anim.setDuration(self.DURATION)
        self._anim.setEasingCurve(QEasingCurve.OutCubic)

    def wheelEvent(self, event):
        delta = event.angleDelta().y()
        if not delta or event.modifiers() & Qt.ControlModifier:
            super().wheelEvent(event)
            return
        bar = self.verticalScrollBar()
        pixel = event.pixelDelta().y()
        if pixel and event.phase() != Qt.NoScrollPhase:      # 触控板：本身就是连续的，直接跟手
            self._anim.stop()
            self._target = None
            bar.setValue(bar.value() - pixel)
            event.accept()
            return
        running = self._anim.state() == QAbstractAnimation.Running and self._target is not None
        start = self._target if running else bar.value()
        self._target = max(bar.minimum(), min(bar.maximum(), int(start - delta / 120 * self.STEP)))
        self._anim.stop()
        self._anim.setStartValue(bar.value())
        self._anim.setEndValue(self._target)
        self._anim.start()
        event.accept()


class NoWheelComboBox(QComboBox):
    """下拉框：只能点击选择。滚轮事件交给外面的页面去滚动，
    避免滚动设置页面时鼠标经过下拉框，不知不觉改掉了选项"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.setFocusPolicy(Qt.StrongFocus)      # 不让滚轮把焦点给它

    def wheelEvent(self, event):
        event.ignore()


class ElidedLabel(QLabel):
    """文字太长时，中间用 … 省略（路径的开头和结尾都能看到）"""

    def minimumSizeHint(self):
        return QSize(40, super().minimumSizeHint().height())

    def paintEvent(self, event):
        p = QPainter(self)
        p.setPen(self.palette().color(self.foregroundRole()))
        text = self.fontMetrics().elidedText(self.text(), Qt.ElideMiddle, self.width())
        p.drawText(self.rect(), Qt.AlignLeft | Qt.AlignVCenter, text)
        p.end()


def card():
    frame = QFrame()
    frame.setObjectName("card")
    return frame


def label(text, name=None, wrap=False):
    lab = QLabel(text)
    if name:
        lab.setObjectName(name)
    lab.setWordWrap(wrap)
    return lab


class Bridge(QObject):
    """引擎在后台线程里运行，不能直接改界面；通过信号把消息送回界面线程"""
    log = Signal(str)
    status = Signal(str, str)
    presets_result = Signal(str, object, bool)    # 结果（updated/latest/error）、数据、是否手动检查
    network = Signal(object, str)                 # 网卡原始数据（失败时为 None）、出错原因
    activity = Signal(object)                     # 名单里每一项的实时状态
    self_check = Signal(object)                   # 自检结果
    export_done = Signal(str, str)                # 导出诊断信息：保存路径、出错原因（成功为空）


# ======================================================================
# 对话框：从运行中的程序添加
# ======================================================================

class ProcessPicker(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("从运行中的程序添加")
        self.resize(680, 520)

        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索，例如 edge 或 msedge")
        self.search.textChanged.connect(self.apply_filter)

        self.list = QListWidget()
        self.list.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.list.setIconSize(QSize(20, 20))

        self.mode_path = QRadioButton("只匹配这个位置的程序（推荐）")
        self.mode_name = QRadioButton("匹配所有同名程序")
        self.mode_folder = QRadioButton("匹配它所在文件夹里的所有程序（适合多进程软件）")
        self.mode_path.setChecked(True)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.button(QDialogButtonBox.Ok).setText("添加")
        buttons.button(QDialogButtonBox.Cancel).setText("取消")
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(self.search)
        layout.addWidget(self.list, 1)
        layout.addWidget(label("可以按住 Ctrl 多选。", "hint"))
        for r in (self.mode_path, self.mode_name, self.mode_folder):
            layout.addWidget(r)
        layout.addWidget(buttons)

        self.load_processes()

    def load_processes(self):
        seen = {}
        for p in psutil.process_iter(["name", "exe"]):
            name, exe = p.info["name"], p.info["exe"]
            if name and exe and exe.lower() not in seen:
                seen[exe.lower()] = (name, exe)
        rows = [(file_description(exe) or name, name, exe) for name, exe in seen.values()]
        for title, name, exe in sorted(rows, key=lambda x: x[0].lower()):
            item = QListWidgetItem(exe_icon(exe), f"{title}    —  {exe}")
            item.setData(Qt.UserRole, (name, exe))
            self.list.addItem(item)

    def apply_filter(self, text):
        text = text.lower()
        for i in range(self.list.count()):
            item = self.list.item(i)
            item.setHidden(text not in item.text().lower())

    def selected_entries(self):
        result = []
        for item in self.list.selectedItems():
            name, exe = item.data(Qt.UserRole)
            if self.mode_name.isChecked():
                result.append(name.lower())
            elif self.mode_folder.isChecked():
                result.append(os.path.dirname(exe).lower() + "\\")
            else:
                result.append(exe.lower())
        return result


# ======================================================================
# 设置窗口
# ======================================================================

class SettingsDialog(QDialog):
    def __init__(self, main):
        super().__init__(main)
        self.main = main
        self.setWindowTitle("设置")
        self.setMinimumWidth(560)
        self.resize(700, 720)
        self.boxes = {}

        content = QWidget()
        content.setObjectName("root")
        content.setAttribute(Qt.WA_StyledBackground, True)
        layout = QVBoxLayout(content)
        layout.setSpacing(4)
        scroll = SmoothScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)   # 只上下滚动，宽度始终跟窗口一致
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setWidget(content)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll)

        def option(key, text, hint):
            box = QCheckBox(text)
            box.setChecked(main.options[key])
            box.toggled.connect(lambda checked, k=key: main.set_option(k, checked))
            self.boxes[key] = box
            layout.addWidget(box)
            hint_label = label(hint, "hint", wrap=True)
            hint_label.setContentsMargins(24, 0, 0, 6)
            layout.addWidget(hint_label)

        layout.addWidget(label("常规", "section"))
        self.autostart = QCheckBox("开机自动启动")
        self.autostart.setChecked(autostart_enabled())
        self.autostart.toggled.connect(main.toggle_autostart)
        layout.addWidget(self.autostart)
        hint = label("登录 Windows 后自动在托盘运行；上次退出时正在分流的话，会自动开始。", "hint", wrap=True)
        hint.setContentsMargins(24, 0, 0, 6)
        layout.addWidget(hint)
        theme_row = QHBoxLayout()
        theme_row.addWidget(QLabel("外观"))
        self.theme_box = NoWheelComboBox()
        for key, text in THEME_CHOICES:
            self.theme_box.addItem(text, key)
        keys = [k for k, _ in THEME_CHOICES]
        self.theme_box.setCurrentIndex(keys.index(main.options.get("theme", "system")) if main.options.get("theme") in keys else 0)
        self.theme_box.currentIndexChanged.connect(lambda i: main.set_theme(self.theme_box.itemData(i)))
        theme_row.addWidget(self.theme_box)
        theme_row.addStretch(1)
        layout.addLayout(theme_row)
        rules_row = QHBoxLayout()
        rules_row.setContentsMargins(0, 6, 0, 0)
        export_btn = QPushButton("导出规则…")
        export_btn.clicked.connect(lambda: main.export_rules(self))
        import_btn = QPushButton("导入规则…")
        import_btn.clicked.connect(lambda: main.import_rules(self))
        rules_row.addWidget(export_btn)
        rules_row.addWidget(import_btn)
        rules_row.addStretch(1)
        layout.addLayout(rules_row)
        hint = label("规则 = 直连名单、勾选的常用软件、自定义域名。可以备份，或者分享给别人直接导入。", "hint", wrap=True)
        hint.setContentsMargins(0, 2, 0, 6)
        layout.addWidget(hint)

        layout.addWidget(label("直连范围", "section"))
        option("children", "子进程也直连",
               "名单里的程序启动的其他程序也直连，例如启动器打开的游戏、软件内嵌的网页。")

        layout.addWidget(label("DNS", "section"))
        option("dns", "直连程序的 DNS 交给国内 DNS 解析",
               "Chrome、Edge 等自己发 DNS 查询的直连程序，改由国内 DNS 解析，得到离你近的服务器。")

        layout.addWidget(label("常用软件：勾选后，它们的域名交给国内 DNS 解析", wrap=True))
        hint = label("抖音、QQ、微信等使用 Windows 系统 DNS 的软件需要在这里勾选；"
                     "没勾选的域名照常由 VPN 的 DNS 解析，不会泄漏。", "hint", wrap=True)
        hint.setContentsMargins(0, 0, 0, 4)
        layout.addWidget(hint)
        grid = QGridLayout()
        grid.setHorizontalSpacing(16)
        for col in range(4):
            grid.setColumnStretch(col, 1)       # 四列平均分配宽度
        self.preset_boxes = {}
        for i, (key, (title, domains)) in enumerate(main.presets.items()):
            short = title.split("（")[0]
            box = QCheckBox(short)
            box.setToolTip(f"{title}\n共 {len(domains)} 个域名")
            box.setChecked(key in main.options["domain_presets"])
            box.toggled.connect(self.presets_changed)
            self.preset_boxes[key] = box
            grid.addWidget(box, i // 4, i % 4)
        layout.addLayout(grid)
        # 提示条：勾选了但没加直连（会绕路）、加了直连但没勾选（不是最近的节点）
        self.advice = QFrame()
        self.advice.setObjectName("banner")
        self.advice_text = label("", wrap=True)
        self.advice_btn = QPushButton("一键勾选建议的项")
        self.advice_btn.setObjectName("accent")
        self.advice_btn.setCursor(Qt.PointingHandCursor)
        self.advice_btn.clicked.connect(self.apply_advice)
        advice_row = QHBoxLayout(self.advice)
        advice_row.setContentsMargins(12, 8, 8, 8)
        advice_row.addWidget(self.advice_text, 1)
        advice_row.addWidget(self.advice_btn, 0, Qt.AlignVCenter)
        layout.addWidget(self.advice)
        self.update_advice()

        self.presets_label = label("", "hint", wrap=True)
        self.update_presets_label()
        self.presets_btn = QPushButton("↻ 检查更新")
        self.presets_btn.setObjectName("accent")
        self.presets_btn.setCursor(Qt.PointingHandCursor)
        self.presets_btn.clicked.connect(lambda: main.check_presets(manual=True))
        source = QHBoxLayout()
        source.setContentsMargins(0, 2, 0, 8)
        source.addWidget(self.presets_label, 1)
        source.addWidget(self.presets_btn)
        layout.addLayout(source)

        layout.addWidget(label("自定义域名（每行一个，子域名自动包含）：", wrap=True))
        self.domains = QPlainTextEdit("\n".join(main.options.get("local_domains", [])))
        self.domains.setPlaceholderText("上面没有的软件，把它的域名填在这里，例如：\nexample.com")
        self.domains.setFixedHeight(90)
        self.save_timer = QTimer(self)
        self.save_timer.setSingleShot(True)
        self.save_timer.timeout.connect(self.domains_changed)
        self.domains.textChanged.connect(lambda: self.save_timer.start(800))   # 停止输入 0.8 秒后保存
        layout.addWidget(self.domains)

        finder = QPushButton("查找软件用到的域名…")
        finder.clicked.connect(main.show_domain_finder)
        self.doh_box = NoWheelComboBox()
        for key, text in DOH_CHOICES:
            self.doh_box.addItem(text, key)
        doh_keys = [k for k, _ in DOH_CHOICES]
        current = main.options.get("doh", "ali")
        self.doh_box.setCurrentIndex(doh_keys.index(current) if current in doh_keys else 0)
        self.doh_box.currentIndexChanged.connect(
            lambda i: main.set_option("doh", self.doh_box.itemData(i)))
        row = QHBoxLayout()
        row.addWidget(finder)
        row.addStretch(1)
        row.addWidget(QLabel("国内 DNS 服务"))
        row.addWidget(self.doh_box)
        layout.addLayout(row)
        hint = label("国内 DNS 通过 HTTPS 加密查询，从本地网卡发出；即使 VPN 开了“禁止 VPN 外的 DNS”也能用。",
                     "hint", wrap=True)
        hint.setContentsMargins(0, 2, 0, 6)
        layout.addWidget(hint)

        layout.addWidget(label("IPv6", "section"))
        option("ipv6", "自动处理 IPv6",
               "VPN 不支持 IPv6 时，拦截非直连程序的 IPv6，防止它们绕过 VPN；VPN 支持时，让直连程序改用 IPv4。")

        layout.addWidget(label("网卡", "section"))
        hint = label("一般保持“自动识别”。用的不是 OpenVPN（例如 WireGuard），或者电脑有多个网卡、识别错了，"
                     "可以在这里手动选择。", "hint", wrap=True)
        hint.setContentsMargins(0, 0, 0, 4)
        layout.addWidget(hint)
        nic = QGridLayout()
        nic.setHorizontalSpacing(10)
        nic.setColumnStretch(1, 1)
        self.vpn_box = NoWheelComboBox()
        self.local_box = NoWheelComboBox()
        for box in (self.vpn_box, self.local_box):
            box.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
            box.setMinimumContentsLength(20)
        self.vpn_box.currentIndexChanged.connect(lambda i: self.adapter_chosen("vpn_adapter", self.vpn_box))
        self.local_box.currentIndexChanged.connect(lambda i: self.adapter_chosen("local_adapter", self.local_box))
        self.nic_refresh = QPushButton("刷新")
        self.nic_refresh.clicked.connect(self.load_adapters)
        nic.addWidget(QLabel("VPN 网卡"), 0, 0)
        nic.addWidget(self.vpn_box, 0, 1)
        nic.addWidget(self.nic_refresh, 0, 2)
        nic.addWidget(QLabel("本地网卡"), 1, 0)
        nic.addWidget(self.local_box, 1, 1)
        layout.addLayout(nic)
        self.nic_result = label("正在读取网卡……", "hint", wrap=True)
        self.nic_result.setContentsMargins(0, 2, 0, 4)
        layout.addWidget(self.nic_result)
        kw_row = QHBoxLayout()
        kw_row.addWidget(QLabel("额外的 VPN 关键字"))
        self.keywords = QLineEdit(", ".join(main.options.get("vpn_keywords", [])))
        self.keywords.setPlaceholderText("例如 wireguard, anyconnect（自动识别时使用，用逗号分隔）")
        self.keywords.editingFinished.connect(self.keywords_changed)
        kw_row.addWidget(self.keywords, 1)
        layout.addLayout(kw_row)
        hint = label("自动识别：名称或描述里带 OpenVPN、TAP-Windows、Wintun 的是 VPN 网卡；"
                     "本地网卡从有默认路由的其他网卡里选，跳过 WireGuard、Tailscale、Clash 等隧道网卡，"
                     "优先选有网关的，再按跃点数从小到大。", "hint", wrap=True)
        hint.setContentsMargins(0, 2, 0, 6)
        layout.addWidget(hint)
        main.bridge.network.connect(self.fill_adapters)
        self.adapters_data = None
        self.load_adapters()

        layout.addWidget(label("排查问题", "section"))
        option("verbose", "记录走 VPN 的连接",
               "日志里同时记录走 VPN 的新连接属于哪个程序。日志会很多，排查完记得关掉。")

        close = QPushButton("完成")
        close.clicked.connect(self.accept)
        bottom = QHBoxLayout()
        bottom.setContentsMargins(12, 8, 12, 12)
        bottom.addStretch(1)
        bottom.addWidget(close)
        outer.addLayout(bottom)

    def sync_from_options(self):
        """导入规则后，让设置窗口的显示和当前设置一致"""
        o = self.main.options
        for key, box in self.boxes.items():
            self.set_checked_quietly(box, bool(o[key]))
        for key, box in self.preset_boxes.items():
            self.set_checked_quietly(box, key in o["domain_presets"])
        self.save_timer.stop()
        self.domains.blockSignals(True)
        self.domains.setPlainText("\n".join(o["local_domains"]))
        self.domains.blockSignals(False)
        self.update_advice()

    def load_adapters(self):
        self.nic_refresh.setEnabled(False)
        self.nic_result.setText("正在读取网卡……")
        self.main.query_network_async()

    def fill_adapters(self, data, error):
        self.nic_refresh.setEnabled(True)
        if data is None:
            self.nic_result.setText(f"读取网卡失败：{error}")
            return
        self.adapters_data = data
        rows = adapter_rows(data)
        extra = self.main.options.get("vpn_keywords", [])
        for box, key in ((self.vpn_box, "vpn_adapter"), (self.local_box, "local_adapter")):
            current = self.main.options.get(key, "")
            box.blockSignals(True)
            box.clear()
            box.addItem("自动识别", "")
            ordered = sorted(rows, key=lambda r: (not is_vpn_adapter(r, extra)) if key == "vpn_adapter"
                             else (not r["default_route"], r["metric"] or 0))
            for r in ordered:
                box.addItem(f"{r['name']}  ·  {r['ip'] or '没有 IPv4 地址'}", r["name"])
                box.setItemData(box.count() - 1, r["desc"], Qt.ToolTipRole)
            names = [box.itemData(i) or "" for i in range(box.count())]
            if current and current not in names:
                box.addItem(f"{current}（当前未连接）", current)
                names.append(current)
            # 自己逐项比较，不用 findData：空字符串（自动识别）在不同 Qt 版本里匹配结果不可靠
            box.setCurrentIndex(names.index(current) if current in names else 0)
            box.blockSignals(False)
        self.update_nic_result()

    def update_nic_result(self):
        if self.adapters_data is None:
            return
        rows = {r["index"]: r for r in adapter_rows(self.adapters_data)}
        try:
            ad = parse_adapters(self.adapters_data, self.main.options)
        except Exception as e:
            self.nic_result.setText(f"⚠ {e}")
            return
        vpn, local = rows[ad.vpn_index], rows[ad.local_index]
        self.nic_result.setText(f"✔ 将使用：VPN 网卡 {vpn['name']}（{ad.vpn_ip}），"
                                f"本地网卡 {local['name']}（{ad.local_ip}）")

    def adapter_chosen(self, key, box):
        self.main.set_option(key, (box.currentData() or "") if box.currentIndex() > 0 else "")
        self.update_nic_result()

    def keywords_changed(self):
        words = [w.strip() for w in self.keywords.text().replace("，", ",").split(",") if w.strip()]
        self.main.set_option("vpn_keywords", words)
        self.update_nic_result()

    def set_checked_quietly(self, box, checked):
        box.blockSignals(True)             # 改回原状态时不要再触发处理函数
        box.setChecked(checked)
        box.blockSignals(False)

    def update_presets_label(self):
        m = self.main
        self.presets_label.setText(
            f"域名来自社区维护的 v2fly/domain-list-community，当前版本 {m.presets_version}（{m.presets_date}），"
            f"共 {preset_updater.total(m.presets)} 个域名。")
        for key, box in getattr(self, "preset_boxes", {}).items():
            if key in m.presets:
                title, domains = m.presets[key]
                box.setToolTip(f"{title}\n共 {len(domains)} 个域名")

    def presets_changed(self):
        keys = [k for k, box in self.preset_boxes.items() if box.isChecked()]
        self.main.set_option("domain_presets", keys)
        self.update_advice()

    def update_advice(self):
        unmatched, suggest = self.main.preset_advice()
        self.suggested = list(suggest)
        lines = []
        if unmatched:
            names = "、".join(self.main.preset_title(k) for k in unmatched)
            lines.append(f"⚠ 已勾选 {names}，但主页面没有开启它们的程序：这些软件会解析到国内服务器，"
                         f"却仍然经 VPN 去连接，绕路反而更慢。请在主页面加入对应程序，或取消勾选。")
        if suggest:
            apps = "；".join(f"{'、'.join(v)} → {self.main.preset_title(k)}" for k, v in suggest.items())
            lines.append(f"💡 主页面这些直连程序有对应的域名，建议勾选：{apps}")
        self.advice_text.setText("\n".join(lines))
        self.advice_btn.setVisible(bool(suggest))
        self.advice.setVisible(bool(lines))

    def apply_advice(self):
        for key in self.suggested:
            if key in self.preset_boxes:
                self.set_checked_quietly(self.preset_boxes[key], True)
        self.presets_changed()

    def domains_changed(self):
        self.save_timer.stop()
        self.main.set_option("local_domains", clean_domains(self.domains.toPlainText()))

    def closeEvent(self, event):
        if self.save_timer.isActive():        # 关窗口时还有没保存的修改，立刻保存
            self.domains_changed()
        super().closeEvent(event)

    def accept(self):
        if self.save_timer.isActive():
            self.domains_changed()
        super().accept()


# ======================================================================
# 查找软件用到的域名
# ======================================================================

class DomainFinder(QDialog):
    """边用软件边记录：列出这段时间里“走 VPN 解析”的域名，勾选后加进自定义域名"""

    def __init__(self, main):
        super().__init__(main)
        self.main = main
        self.setWindowTitle("查找软件用到的域名")
        self.resize(620, 560)
        self.items = {}                                   # 域名 -> 列表里的那一行

        steps = label(
            "1. 点“开始查找”（会自动清空系统 DNS 缓存）\n"
            "2. 正常使用要直连的软件几分钟：登录、发消息、看图片、打开各个功能\n"
            "3. 在下面勾选属于这个软件的域名，点“加入自定义域名”", wrap=True)
        hint = label("列表里只显示还在走 VPN 解析的域名；其他正在联网的软件的域名也会出现，"
                     "只勾选你认识、属于这个软件的。", "hint", wrap=True)

        self.toggle_btn = QPushButton("开始查找")
        self.toggle_btn.setObjectName("primary")
        self.toggle_btn.clicked.connect(self.toggle)
        clear = QPushButton("清空列表")
        clear.clicked.connect(self.clear)
        self.status = label("", "hint")
        top = QHBoxLayout()
        top.addWidget(self.toggle_btn)
        top.addWidget(clear)
        top.addWidget(self.status, 1)

        self.search = QLineEdit()
        self.search.setPlaceholderText("筛选，例如 qq、weixin")
        self.search.textChanged.connect(self.apply_filter)
        self.list = QListWidget()
        self.list.setObjectName("panel")

        self.use_base = QCheckBox("按主域名添加（推荐）：例如 img.wxgateway.com 加成 wxgateway.com，一次包含所有子域名")
        self.use_base.setChecked(True)
        self.use_base.toggled.connect(self.refresh_labels)
        add = QPushButton("加入自定义域名")
        add.clicked.connect(self.add_selected)
        bottom = QHBoxLayout()
        bottom.addStretch(1)
        bottom.addWidget(add)

        layout = QVBoxLayout(self)
        layout.addWidget(steps)
        layout.addWidget(hint)
        layout.addLayout(top)
        layout.addWidget(self.search)
        layout.addWidget(self.list, 1)
        layout.addWidget(self.use_base)
        layout.addLayout(bottom)

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh)

    def toggle(self):
        engine = self.main.engine
        if engine.capturing:
            engine.stop_capture()
            self.timer.stop()
            self.refresh()
        else:
            if engine.session is None:
                QMessageBox.information(self, "还没开始分流",
                                        "请先在主窗口点“开始分流”，并确认 VPN 已连接，再开始查找。")
                return
            engine.start_capture()
            self.timer.start(1000)
        self.update_button()

    def update_button(self):
        capturing = self.main.engine.capturing
        self.toggle_btn.setText("停止查找" if capturing else "开始查找")
        self.toggle_btn.setObjectName("stop" if capturing else "primary")
        self.toggle_btn.style().unpolish(self.toggle_btn)
        self.toggle_btn.style().polish(self.toggle_btn)

    def clear(self):
        self.main.engine.captured = {}
        self.items = {}
        self.list.clear()
        self.refresh()

    def text_for(self, name, count):
        base = base_domain(name)
        if self.use_base.isChecked() and base != name:
            return f"{name}    →  添加为 {base}    （{count} 次）"
        return f"{name}    （{count} 次）"

    def refresh(self):
        captured = dict(self.main.engine.captured)          # 复制一份，避免后台线程同时修改
        local = set(self.main.all_local_domains())
        for name, (count, _first) in sorted(captured.items(), key=lambda x: x[1][1]):
            if domain_matches(name, local):                 # 已经在本地解析列表里了，不用再显示
                if name in self.items:
                    self.list.takeItem(self.list.row(self.items.pop(name)))
                continue
            item = self.items.get(name)
            if item is None:
                item = QListWidgetItem()
                item.setFlags(item.flags() | Qt.ItemIsUserCheckable)
                item.setCheckState(Qt.Unchecked)
                item.setData(Qt.UserRole, name)
                self.items[name] = item
                self.list.addItem(item)
            item.setData(Qt.UserRole + 1, count)
            item.setText(self.text_for(name, count))
        self.apply_filter(self.search.text())
        state = "正在记录…" if self.main.engine.capturing else "已停止"
        self.status.setText(f"{state}  共 {len(self.items)} 个域名")

    def refresh_labels(self):
        for name, item in self.items.items():
            item.setText(self.text_for(name, item.data(Qt.UserRole + 1) or 0))

    def apply_filter(self, text):
        text = text.lower()
        for name, item in self.items.items():
            item.setHidden(bool(text) and text not in name)

    def add_selected(self):
        chosen = [name for name, item in self.items.items() if item.checkState() == Qt.Checked]
        if not chosen:
            QMessageBox.information(self, "没有勾选", "先在列表里勾选要加入的域名。")
            return
        if self.use_base.isChecked():
            chosen = [base_domain(n) for n in chosen]
        chosen = list(dict.fromkeys(chosen))                # 去重，保持顺序
        added = self.main.add_custom_domains(chosen)
        self.refresh()
        QMessageBox.information(self, "已加入",
                                f"已加入 {added} 个域名：\n" + "\n".join(chosen[:20])
                                + ("\n…" if len(chosen) > 20 else "")
                                + "\n\n建议重启一下这个软件，让它重新解析域名。")

    def closeEvent(self, event):
        if self.main.engine.capturing:                    # 关窗口就停止记录
            self.main.engine.stop_capture()
            self.timer.stop()
            self.update_button()
        super().closeEvent(event)


# ======================================================================
# 一键自检
# ======================================================================

def self_check(engine, options, unmatched, suggest, enabled, titles, preset_titles, status):
    """逐项检查，返回 [(级别, 项目, 说明)]；级别：ok / warn / fail / info。
    在后台线程里运行：只用传进来的数据，不碰界面"""
    R = []

    # 1. 管理员权限
    try:
        admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        admin = False
    R.append(("ok", "管理员权限", "已获得") if admin else
             ("fail", "管理员权限", "没有管理员权限，无法加载网络驱动。请右键“以管理员身份运行”"))

    # 2. WinDivert 驱动
    if engine.session is not None:
        R.append(("ok", "WinDivert 驱动", "正在使用"))
    else:
        ok, err = driver_check()
        R.append(("ok", "WinDivert 驱动", "可以正常加载") if ok else
                 ("fail", "WinDivert 驱动", f"加载失败：{err}\n"
                  "可能被安全软件拦截，或者驱动文件不完整；可以重启电脑后再试，或重新下载程序"))

    # 3. 网卡
    ad = None
    try:
        data = query_network()
    except AdapterQueryError as e:
        data = None
        R.append(("fail", "读取网卡信息", f"{e}。可以稍后点“重新检查”"))
    if data is not None:
        rows = adapter_rows(data)
        by_index = {r["index"]: r for r in rows}
        try:
            ad = parse_adapters(data, options)
        except Exception as e:
            listing = "\n".join(f"    {r['name']}（{r['desc']}）  {r['ip'] or '没有 IPv4'}"
                                f"{'  有默认路由' if r['default_route'] else ''}" for r in rows) or "    无"
            R.append(("fail", "网卡识别", f"{e}\n当前已连接的网卡：\n{listing}"))
        if ad is not None:
            vpn, local = by_index[ad.vpn_index], by_index[ad.local_index]
            how_v = "手动指定" if options.get("vpn_adapter") else "自动识别"
            how_l = "手动指定" if options.get("local_adapter") else "自动识别"
            R.append(("ok", "VPN 网卡", f"{vpn['name']}（{vpn['desc']}），IP {ad.vpn_ip}，{how_v}"))
            R.append(("ok", "本地网卡", f"{local['name']}（{local['desc']}），IP {ad.local_ip}，"
                                       f"DNS {ad.local_dns}，{how_l}"))
            if not local["default_route"]:
                R.append(("warn", "本地网卡的默认路由",
                          "手动选择的本地网卡没有默认路由，直连的流量可能发不出去"))
            if not options.get("ipv6"):
                R.append(("info", "IPv6", "自动处理已关闭"))
            elif ad.vpn_v6:
                R.append(("info", "IPv6", "VPN 支持 IPv6 → 拦截直连程序的 IPv6，让它们用 IPv4 直连"))
            elif ad.local_v6:
                R.append(("info", "IPv6", "VPN 不支持、本地网络支持 IPv6 → 拦截非直连程序的 IPv6，防止绕过 VPN"))
            else:
                R.append(("info", "IPv6", "VPN 和本地网络都没有公网 IPv6，不需要处理"))

    # 4. 国内 DNS（从本地网卡发 DoH 查询）
    if ad is not None:
        client = None
        try:
            client = DohClient(ad.local_ip, options.get("doh", "ali"), None, None, workers=0)
            ok, ms, err = client.test()
        except Exception as e:
            ok, ms, err = False, None, e
        name = client.name if client else options.get("doh")
        R.append(("ok", "国内 DNS", f"{name} 从本地网卡查询正常，用时 {ms:.0f}ms") if ok else
                 ("fail", "国内 DNS", f"从本地网卡连不上 {name}（{err}）。\n"
                  "需要国内解析的域名会退回 VPN 的 DNS；可以在设置里换一个国内 DNS 服务再试"))
    else:
        R.append(("info", "国内 DNS", "网卡识别失败，跳过"))

    # 5. 系统代理
    try:
        proxy = system_proxy()
    except Exception:
        proxy = None
    R.append(("warn", "系统代理", f"已开启（{proxy}）。浏览器等跟随系统代理的程序，流量会交给代理软件，"
                                "不会直连。需要时在 v2rayN、Clash 等软件里清除系统代理") if proxy else
             ("ok", "系统代理", "未开启"))

    # 6. 分流状态
    state, title, sub, paused = status
    if paused:
        R.append(("warn", "分流状态", f"{title}：{sub}"))
    elif engine.running:
        level = "ok" if state == "running" else "fail" if state == "error" else "warn"
        R.append((level, "分流状态", f"{title}    {sub}"))
        sockets = engine.sockets
        R.append(("ok", "程序识别（SOCKET 层）", "可用，新连接能立即认出属于哪个程序")
                 if sockets is not None and sockets.ok else
                 ("warn", "程序识别（SOCKET 层）", "不可用，改为扫描连接表识别，稍慢，不影响使用"))
    else:
        R.append(("warn", "分流状态", "没有开启，所有程序都走 VPN。点主页面的“开始分流”"))

    # 7. 名单里的程序
    if not enabled:
        R.append(("warn", "直连名单", "名单里没有开启的程序，点主页面的“添加程序”"))
    else:
        activity = engine.app_activity(enabled)
        for m in enabled:
            running, conns = activity.get(m, (0, 0))
            name = titles.get(m, m)
            if conns and engine.running:
                R.append(("ok", f"程序：{name}", f"{conns} 个直连连接（最近 30 秒内有流量）"))
            elif running and engine.running:
                R.append(("info", f"程序：{name}",
                          f"正在运行（{running} 个进程），最近 30 秒没有直连连接。用它打开个网页再“重新检查”；"
                          f"一直为 0 的话，打开“日志”看有没有它的 [直连] 记录"))
            elif running:
                R.append(("info", f"程序：{name}", f"正在运行（{running} 个进程），分流开启后会直连"))
            else:
                R.append(("info", f"程序：{name}", "没有运行"))

    # 8. 常用软件域名
    if unmatched:
        R.append(("warn", "常用软件域名", "勾选了 " + "、".join(preset_titles.get(k, k) for k in unmatched)
                  + "，但名单里没有对应的程序：这些软件会解析到国内服务器，却经 VPN 去连接，反而更慢"))
    if suggest:
        R.append(("warn", "常用软件域名", "建议在“设置 → DNS”里勾选：" + "；".join(
            f"{'、'.join(v)} → {preset_titles.get(k, k)}" for k, v in suggest.items())))
    return R


CHECK_MARKS = {"ok": ("✔", GREEN), "warn": ("!", "#e0a200"), "fail": ("✖", "#d64545"), "info": ("•", None)}


class SelfCheckDialog(QDialog):
    def __init__(self, main):
        super().__init__(main)
        self.main = main
        self.results = []
        self.running = False
        self.setWindowTitle("一键自检")
        self.resize(680, 600)

        self.summary = label("", "appname", wrap=True)
        self.view = QLabel()
        self.view.setTextFormat(Qt.RichText)
        self.view.setWordWrap(True)
        self.view.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        self.view.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.view.setContentsMargins(4, 4, 4, 4)
        scroll = SmoothScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        scroll.setFrameShape(QFrame.NoFrame)
        body = QWidget()
        body.setObjectName("root")
        body.setAttribute(Qt.WA_StyledBackground, True)
        body_layout = QVBoxLayout(body)
        body_layout.addWidget(self.view)
        body_layout.addStretch(1)
        scroll.setWidget(body)

        self.again = QPushButton("重新检查")
        self.again.setObjectName("accent")
        self.again.clicked.connect(self.run)
        copy_btn = QPushButton("复制结果")
        copy_btn.clicked.connect(self.copy_results)
        nic = QPushButton("网卡设置…")
        nic.clicked.connect(main.show_settings)
        export = QPushButton("导出诊断包")
        export.clicked.connect(lambda: main.export_diagnostics(self))
        buttons = QHBoxLayout()
        buttons.addWidget(self.again)
        buttons.addWidget(copy_btn)
        buttons.addStretch(1)
        buttons.addWidget(nic)
        buttons.addWidget(export)

        layout = QVBoxLayout(self)
        layout.addWidget(self.summary)
        layout.addWidget(scroll, 1)
        layout.addLayout(buttons)
        main.bridge.self_check.connect(self.show_results)

    def run(self):
        if self.running:
            return
        self.running = True
        self.again.setEnabled(False)
        self.summary.setText("正在检查……（大约需要几秒）")
        self.view.setText("")
        self.main.run_self_check_async()

    def show_results(self, results):
        self.running = False
        self.again.setEnabled(True)
        self.results = results
        fails = sum(1 for r in results if r[0] == "fail")
        warns = sum(1 for r in results if r[0] == "warn")
        if fails:
            self.summary.setText(f"发现 {fails} 个问题" + (f"、{warns} 个需要留意的地方" if warns else "")
                                 + "，按红色项的说明处理")
        elif warns:
            self.summary.setText(f"基本正常，有 {warns} 个需要留意的地方")
        else:
            self.summary.setText("一切正常")
        self.render()

    def render(self):
        import html
        rows = []
        for level, title, detail in self.results:
            mark, color = CHECK_MARKS[level]
            color = color or COLORS["sub"]
            detail_html = html.escape(detail).replace("\n", "<br>")
            rows.append(
                f"<tr><td width='26' valign='top' style='color:{color}; font-weight:600; font-size:12pt'>{mark}</td>"
                f"<td style='padding-bottom:10px'><b>{html.escape(title)}</b><br>"
                f"<span style='color:{COLORS['sub']}'>{detail_html}</span></td></tr>")
        self.view.setText("<table cellspacing='0' cellpadding='2'>" + "".join(rows) + "</table>")

    def copy_results(self):
        mark = {"ok": "[正常]", "warn": "[留意]", "fail": "[问题]", "info": "[信息]"}
        lines = [f"{APP_NAME} {APP_VERSION} 自检  {datetime.datetime.now():%Y-%m-%d %H:%M}"]
        for level, title, detail in self.results:
            lines.append(f"{mark[level]} {title}：{detail}")
        QApplication.clipboard().setText("\n".join(lines))
        self.summary.setText(self.summary.text().split("（已复制")[0] + "（已复制到剪贴板）")


# ======================================================================
# 日志窗口
# ======================================================================

class LogDialog(QDialog):
    def __init__(self, main):
        super().__init__(main)
        self.setWindowTitle("日志")
        self.resize(820, 520)
        self.stats = label("", "sub", wrap=True)
        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setMaximumBlockCount(3000)

        open_logs = QPushButton("打开日志文件夹")
        open_logs.clicked.connect(lambda: os.startfile(LOG_DIR))
        export = QPushButton("导出诊断信息")
        export.clicked.connect(lambda: main.export_diagnostics(self))
        buttons = QHBoxLayout()
        buttons.addWidget(self.stats, 1)
        buttons.addWidget(open_logs)
        buttons.addWidget(export)

        layout = QVBoxLayout(self)
        layout.addLayout(buttons)
        layout.addWidget(self.view, 1)


# ======================================================================
# 主窗口
# ======================================================================

class AppRow(QWidget):
    """直连名单里的一行：图标 名字/路径 开关 移除"""

    def __init__(self, main, entry, icon, title, subtitle):
        super().__init__()
        self.entry = entry
        icon_label = QLabel()
        icon_label.setPixmap(icon.pixmap(28, 28))
        icon_label.setFixedSize(32, 32)

        name = label(title, "appname")
        path = ElidedLabel(subtitle)
        path.setObjectName("apppath")
        path.setToolTip(subtitle)
        texts = QVBoxLayout()
        texts.setSpacing(1)
        texts.addWidget(name)
        texts.addWidget(path)

        self.activity = QLabel("")
        self.activity.setObjectName("apppath")
        self.switch = Switch(entry["enabled"])
        self.switch.setToolTip("开 = 直连；关 = 暂时不直连")
        self.switch.toggled.connect(lambda checked: main.set_enabled(entry, checked))
        remove = QPushButton("移除")
        remove.setObjectName("link")
        remove.clicked.connect(lambda: main.remove_entry(entry))

        row = QHBoxLayout(self)
        row.setContentsMargins(10, 8, 6, 8)
        row.setSpacing(10)
        row.addWidget(icon_label)
        row.addLayout(texts, 1)
        row.addWidget(self.activity)
        row.addWidget(self.switch)
        row.addWidget(remove)


    def set_activity(self, enabled, running, connections, engine_on):
        if not enabled:
            text, color, tip = "已关闭", None, "这个程序暂时不直连"
        elif connections:
            text, color = f"● {connections} 个直连连接", GREEN
            tip = "最近 30 秒内有流量的直连连接数"
        elif running:
            text, color = "运行中", None
            tip = ("正在运行，最近 30 秒没有新的直连连接" if engine_on
                   else "正在运行；分流没有开启，它现在走 VPN")
        else:
            text, color, tip = "未运行", None, "没有找到正在运行的这个程序"
        self.activity.setText(text)
        self.activity.setToolTip(tip)
        self.activity.setStyleSheet(f"color: {color}; font-size: 9pt;" if color else "")


class MainWindow(QWidget):
    def __init__(self, server):
        super().__init__()
        self.setObjectName("root")
        self.setAttribute(Qt.WA_StyledBackground, True)   # 让样式表里的背景色生效
        self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
        self.resize(640, 580)
        self.quitting = False
        self.tray_hint_shown = False
        self.state = "stopped"
        self.logger = setup_file_log()
        self.describe_cache = {}

        # 别的 SplitDirect 想启动时，会连到这个 server，叫我们显示窗口
        self.server = server
        self.server.newConnection.connect(self.on_instance_message)

        self.cfg = load_config()
        self.entries = self.cfg["direct_apps"]
        self.load_presets()
        self.presets_checking = False
        self.options = copy.deepcopy(GUI_DEFAULTS)       # 深拷贝：默认值里的列表不能和全局共用
        self.options.update(self.cfg.get("options", {}))
        self.migrate_options()
        self.domain_finder = None

        self.bridge = Bridge()
        self.bridge.log.connect(self.append_log)
        self.bridge.status.connect(self.set_status)
        self.bridge.presets_result.connect(self.on_presets_result)
        self.bridge.activity.connect(self.on_activity)
        self.bridge.export_done.connect(self.on_export_done)
        self.export_parent = None
        self.paused_until = None                         # 暂停分流时：自动恢复的时间
        self.pause_timer = QTimer(self)
        self.pause_timer.setSingleShot(True)
        self.pause_timer.timeout.connect(self.resume)
        self.app_rows = {}
        self.last_activity = {}
        self.activity_busy = False
        self.network_busy = False
        self.self_check_busy = False
        self.self_check_window = None
        self.engine = SplitEngine(on_log=self.bridge.log.emit, on_status=self.bridge.status.emit)
        self.engine.set_options(**{k: v for k, v in self.options.items()
                                    if k in DEFAULT_OPTIONS and k != "local_domains"})
        self.apply_domains()

        self.log_window = LogDialog(self)
        self.settings_window = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 12)
        layout.setSpacing(12)
        layout.addWidget(self.build_status_card())
        layout.addWidget(self.build_banner())
        layout.addWidget(self.build_apps_card(), 1)
        layout.addLayout(self.build_footer())

        self.setup_tray()
        self.update_buttons()
        self.rebuild_list()
        self.set_status("stopped", "未启动")

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.refresh_stats)
        self.timer.start(1000)
        self.activity_timer = QTimer(self)                # 每 3 秒刷新一次名单里每个程序的状态
        self.activity_timer.timeout.connect(self.refresh_activity)
        self.activity_timer.start(3000)

        self.dark = None
        self.refresh_theme()
        self.theme_timer = QTimer(self)                 # 跟随系统时：每 5 秒看一次系统主题有没有变
        self.theme_timer.timeout.connect(self.refresh_theme)
        self.theme_timer.start(5000)

        self.append_log(f"{APP_NAME} {APP_VERSION} 已启动")
        if self.cfg.get("running"):          # 上次退出时正在分流，这次就自动开始
            self.start_engine()
        # 距离上次检查超过 7 天：启动 30 秒后在后台检查一次常用软件域名的更新
        if time.time() - self.cfg.get("presets_checked", 0) > PRESETS_CHECK_DAYS * 86400:
            QTimer.singleShot(30_000, lambda: self.check_presets(manual=False))

    # ----- 常用软件的域名预设：加载、联网更新 -----

    def load_presets(self):
        """先用程序自带的预设，再用联网更新过的覆盖（新版程序可能多了分组，所以按分组合并）"""
        self.presets = dict(domain_presets.PRESETS)
        self.presets_version, self.presets_date = domain_presets.VERSION, domain_presets.DATE
        saved = preset_updater.load_saved(PRESETS_FILE)
        if saved and saved["date"] >= domain_presets.DATE:
            self.presets.update(saved["presets"])
            self.presets_version, self.presets_date = saved["version"], saved["date"]

    def check_presets(self, manual):
        if self.presets_checking:
            return
        self.presets_checking = True
        if manual and self.settings_window is not None:
            self.settings_window.presets_btn.setText("检查中…")
            self.settings_window.presets_btn.setEnabled(False)
        version, count = self.presets_version, preset_updater.total(self.presets)

        def work():                                   # 在后台线程里联网，界面不会卡住
            try:
                status, data = preset_updater.check_update(version, count)
                if status == "updated":
                    preset_updater.save(PRESETS_FILE, data)
                self.bridge.presets_result.emit(status, data, manual)
            except Exception as e:
                self.bridge.presets_result.emit("error", str(e), manual)

        threading.Thread(target=work, daemon=True).start()

    def on_presets_result(self, status, data, manual):
        self.presets_checking = False
        if status != "error":
            self.cfg["presets_checked"] = time.time()
            save_config(self.cfg)
        if status == "updated":
            old_total = preset_updater.total(self.presets)
            self.presets.update({k: (v[0], v[1]) for k, v in data["presets"].items()})
            self.presets_version, self.presets_date = data["version"], data["date"]
            self.apply_domains()                      # 立即生效
            text = (f"常用软件的域名已更新到 {self.presets_version}（{self.presets_date}），"
                    f"共 {preset_updater.total(self.presets)} 个域名（原来 {old_total} 个）")
        elif status == "latest":
            text = f"常用软件的域名已是最新（{self.presets_version}，{self.presets_date}）"
        else:
            text = f"检查常用软件域名更新失败：{data}"
        if manual or status != "latest":
            self.append_log(text)
        win = self.settings_window
        if win is not None:
            win.update_presets_label()
            win.presets_btn.setText("↻ 检查更新")
            win.presets_btn.setEnabled(True)
        if manual:
            QMessageBox.information(win or self, "检查更新", text)

    def migrate_options(self):
        """检查配置文件里的设置：去掉不认识的项，类型或取值不对的恢复默认"""
        changed = False
        for key in list(self.options):
            if key not in GUI_DEFAULTS:
                self.options.pop(key)
                changed = True
            elif type(self.options[key]) is not type(GUI_DEFAULTS[key]):   # 类型不对（配置被改坏）：恢复默认
                self.options[key] = copy.deepcopy(GUI_DEFAULTS[key])
                changed = True
        if self.options["doh"] not in dict(DOH_CHOICES):                 # 取值不认识：恢复默认
            self.options["doh"] = GUI_DEFAULTS["doh"]
            changed = True
        if self.options["theme"] not in dict(THEME_CHOICES):
            self.options["theme"] = GUI_DEFAULTS["theme"]
            changed = True
        self.options["local_domains"] = [d for d in self.options["local_domains"] if isinstance(d, str)]
        self.options["domain_presets"] = [k for k in self.options["domain_presets"] if isinstance(k, str)]
        self.options["vpn_keywords"] = [k for k in self.options["vpn_keywords"] if isinstance(k, str) and k.strip()]
        if changed:
            self.cfg["options"] = self.options
            save_config(self.cfg)

    def all_local_domains(self):
        """引擎实际使用的域名 = 勾选的预设 + 自定义域名"""
        result = list(self.options["local_domains"])
        for key in self.options["domain_presets"]:
            if key in self.presets:
                result += self.presets[key][1]
        return result

    def apply_domains(self):
        self.engine.set_options(local_domains=self.all_local_domains())

    # ----- 界面各部分 -----

    def build_status_card(self):
        frame = card()
        self.dot = QLabel()
        self.dot.setFixedSize(14, 14)
        self.title = label("未开启", "title")
        self.subtitle = label("", "sub")
        texts = QVBoxLayout()
        texts.setSpacing(2)
        head = QHBoxLayout()
        head.setSpacing(10)
        head.addWidget(self.dot)
        head.addWidget(self.title)
        head.addStretch(1)
        texts.addLayout(head)
        texts.addWidget(self.subtitle)

        self.toggle_btn = QPushButton("开始分流")
        self.toggle_btn.setCursor(Qt.PointingHandCursor)
        self.toggle_btn.clicked.connect(self.toggle)

        self.pause_btn = QPushButton(f"暂停 {PAUSE_MINUTES} 分钟")
        self.pause_btn.setObjectName("link")
        self.pause_btn.setCursor(Qt.PointingHandCursor)
        self.pause_btn.setToolTip(f"暂时让所有程序走 VPN，{PAUSE_MINUTES} 分钟后自动恢复分流")
        self.pause_btn.clicked.connect(lambda: self.pause(PAUSE_MINUTES))
        buttons = QVBoxLayout()
        buttons.setSpacing(2)
        buttons.addWidget(self.toggle_btn)
        buttons.addWidget(self.pause_btn, 0, Qt.AlignHCenter)

        row = QHBoxLayout(frame)
        row.setContentsMargins(18, 16, 18, 16)
        row.addLayout(texts, 1)
        row.addLayout(buttons)
        return frame

    def build_banner(self):
        self.banner = QFrame()
        self.banner.setObjectName("banner")
        self.banner_text = label("", wrap=True)
        more = QPushButton("查看日志")
        more.setObjectName("link")
        more.clicked.connect(self.show_logs)
        close = QPushButton("×")
        close.setObjectName("link")
        close.clicked.connect(self.banner.hide)
        row = QHBoxLayout(self.banner)
        row.setContentsMargins(12, 8, 6, 8)
        row.addWidget(self.banner_text, 1)
        row.addWidget(more, 0, Qt.AlignTop)
        row.addWidget(close, 0, Qt.AlignTop)
        self.banner.hide()
        return self.banner

    def build_apps_card(self):
        frame = card()
        head = QHBoxLayout()
        head.addWidget(label("直连的程序", "appname"))
        head.addWidget(label("其余程序继续走 VPN", "hint"))
        head.addStretch(1)
        add = QPushButton("＋ 添加程序")
        add.setCursor(Qt.PointingHandCursor)
        menu = QMenu(add)
        menu.addAction("从运行中的程序选择…", self.add_from_running)
        menu.addAction("选择程序文件（.exe）…", self.add_from_file)
        menu.addAction("选择文件夹（里面所有程序都直连）…", self.add_from_folder)
        menu.addAction("输入程序名…", self.add_by_name)
        add.setMenu(menu)
        head.addWidget(add)

        self.app_list = QListWidget()
        self.app_list.setSelectionMode(QAbstractItemView.NoSelection)
        self.app_list.setFocusPolicy(Qt.NoFocus)
        self.app_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.app_list.customContextMenuRequested.connect(self.show_row_menu)
        self.empty_hint = label("还没有添加程序。点右上角“添加程序”，选择要直连的软件。", "empty", wrap=True)
        self.empty_hint.setAlignment(Qt.AlignCenter)

        layout = QVBoxLayout(frame)
        layout.setContentsMargins(16, 14, 16, 10)
        layout.addLayout(head)
        layout.addWidget(self.app_list, 1)
        layout.addWidget(self.empty_hint, 1)
        return frame

    def build_footer(self):
        self.footer_stats = label("", "hint")
        settings = QPushButton("设置")
        settings.setObjectName("link")
        settings.clicked.connect(self.show_settings)
        logs = QPushButton("日志")
        logs.setObjectName("link")
        logs.clicked.connect(self.show_logs)
        check = QPushButton("自检")
        check.setObjectName("link")
        check.setToolTip("一键检查：管理员权限、驱动、网卡、国内 DNS、系统代理、名单里的程序")
        check.clicked.connect(self.show_self_check)
        row = QHBoxLayout()
        row.setContentsMargins(4, 0, 0, 0)
        row.addWidget(self.footer_stats, 1)
        row.addWidget(check)
        row.addWidget(settings)
        row.addWidget(logs)
        return row

    # ----- 直连名单 -----

    def describe(self, match):
        if match not in self.describe_cache:
            self.describe_cache[match] = describe_entry(match)
        return self.describe_cache[match]

    def rebuild_list(self):
        self.app_list.clear()
        self.app_rows = {}
        for entry in self.entries:
            icon, title, subtitle = self.describe(entry["match"])
            row = AppRow(self, entry, icon, title, subtitle)
            self.app_rows[entry["match"]] = row
            item = QListWidgetItem()
            item.setSizeHint(row.sizeHint())
            item.setData(Qt.UserRole, entry["match"])
            self.app_list.addItem(item)
            self.app_list.setItemWidget(item, row)
        empty = not self.entries
        self.app_list.setVisible(not empty)
        self.empty_hint.setVisible(empty)
        self.on_activity(self.last_activity)
        QTimer.singleShot(0, self.refresh_activity)

    def entry_at(self, pos):
        item = self.app_list.itemAt(pos)
        if item is None:
            return None
        match = item.data(Qt.UserRole)
        return next((e for e in self.entries if e["match"] == match), None)

    def show_row_menu(self, pos):
        entry = self.entry_at(pos)
        if entry is None:
            return
        menu = QMenu(self)
        toggle = menu.addAction("暂停直连" if entry["enabled"] else "恢复直连")
        remove = menu.addAction("移除")
        chosen = menu.exec(self.app_list.viewport().mapToGlobal(pos))
        if chosen == toggle:
            self.set_enabled(entry, not entry["enabled"])
            self.rebuild_list()
        elif chosen == remove:
            self.remove_entry(entry)

    def set_enabled(self, entry, enabled):
        entry["enabled"] = enabled
        self.apps_changed()

    def remove_entry(self, entry):
        title = self.describe(entry["match"])[1]
        answer = QMessageBox.question(self, "移除", f"不再让“{title}”直连吗？")
        if answer != QMessageBox.Yes:
            return
        self.entries.remove(entry)
        # 稍后再刷新列表：这时“移除”按钮还在处理自己的点击，立刻删掉它可能导致崩溃
        QTimer.singleShot(0, self.rebuild_list)
        self.apps_changed()

    def add_entries(self, matches):
        existing = {e["match"] for e in self.entries}
        added = []
        for m in matches:
            m = m.strip().lower()
            if m and m not in existing:
                self.entries.append({"match": m, "enabled": True})
                existing.add(m)
                added.append(m)
        self.rebuild_list()
        self.apps_changed()
        self.suggest_presets(added)

    def preset_title(self, key):
        return self.presets[key][0].split("（")[0] if key in self.presets else key

    def suggest_presets(self, matches):
        """刚加入的程序属于某个还没勾选的预设：提示一键勾选"""
        missing = {}                                   # 预设 -> [程序名...]
        for m in matches:
            title = self.describe(m)[1]
            for key in presets_for_app(m, title):
                if key in self.presets and key not in self.options["domain_presets"]:
                    missing.setdefault(key, []).append(title)
        if not missing:
            return
        lines = "\n".join(f"  • {'、'.join(apps)} → {self.preset_title(k)}" for k, apps in missing.items())
        answer = QMessageBox.question(
            self, "建议同时勾选域名",
            f"{lines}\n\n建议在“设置 → DNS”里同时勾选上面的域名，让这些软件解析到离你最近的国内服务器。"
            f"只加直连、不勾选域名的话，它们可能连到海外节点，速度会慢一些。\n\n现在勾选吗？")
        if answer == QMessageBox.Yes:
            self.set_option("domain_presets", self.options["domain_presets"] + list(missing))
            self.sync_preset_boxes()

    def sync_preset_boxes(self):
        """设置窗口开着的话，让勾选框和当前设置一致"""
        win = self.settings_window
        if win is None:
            return
        for key, box in win.preset_boxes.items():
            win.set_checked_quietly(box, key in self.options["domain_presets"])
        win.update_advice()

    def add_from_running(self):
        QApplication.setOverrideCursor(Qt.WaitCursor)
        try:
            dlg = ProcessPicker(self)
        finally:
            QApplication.restoreOverrideCursor()
        dlg.winId()                                     # 先创建窗口句柄，才能设置标题栏颜色
        set_dark_titlebar(dlg, bool(self.dark))
        if dlg.exec() == QDialog.Accepted:
            self.add_entries(dlg.selected_entries())

    def add_from_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "选择程序", "C:\\", "程序 (*.exe)")
        if path:
            self.add_entries([os.path.normpath(path)])

    def add_from_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "选择文件夹（里面的所有程序都会直连）", "C:\\")
        if folder:
            self.add_entries([os.path.normpath(folder).rstrip("\\") + "\\"])

    def add_by_name(self):
        name, ok = QInputDialog.getText(self, "输入程序名", "程序名（所有同名程序都会直连），例如 curl.exe：")
        name = name.strip()
        if ok and name:
            if not name.lower().endswith(".exe"):
                name += ".exe"
            self.add_entries([name])

    def apps_changed(self):
        self.cfg["direct_apps"] = self.entries
        save_config(self.cfg)
        self.engine.set_apps([e["match"] for e in self.entries if e["enabled"]])
        if self.settings_window is not None:
            self.settings_window.update_advice()

    def preset_advice(self):
        """检查两种容易设错的情况，返回 (勾选了但没有对应直连程序的预设, {有直连程序但没勾选的预设: [程序名]})"""
        covered, suggest = set(), {}
        for e in self.entries:
            if not e["enabled"]:
                continue
            title = self.describe(e["match"])[1]
            for key in presets_for_app(e["match"], title):
                if key not in self.presets:
                    continue
                covered.add(key)
                if key not in self.options["domain_presets"]:
                    suggest.setdefault(key, []).append(title)
        unmatched = [k for k in self.options["domain_presets"] if k in self.presets and k not in covered]
        return unmatched, suggest

    # ----- 设置 -----

    # ----- 外观 -----

    def want_dark(self):
        theme = self.options.get("theme", "system")
        return system_dark_mode() if theme == "system" else theme == "dark"

    def refresh_theme(self, force=False):
        dark = self.want_dark()
        if force or dark != self.dark:
            self.dark = dark
            apply_theme(dark)
            if self.self_check_window is not None and self.self_check_window.results:
                self.self_check_window.render()       # 自检结果里的颜色跟着主题变

    def set_theme(self, theme):
        self.options["theme"] = theme
        self.save_options()
        self.refresh_theme(force=True)

    def present(self, window):
        """显示一个窗口：标题栏配色跟主题一致，并放到最前面"""
        window.show()
        set_dark_titlebar(window, bool(self.dark))
        window.raise_()
        window.activateWindow()

    def show_settings(self):
        if self.settings_window is None:
            self.settings_window = SettingsDialog(self)
        else:
            self.settings_window.load_adapters()       # 网卡可能变了：每次打开都重新读一次
        self.present(self.settings_window)

    def set_option(self, key, value):
        if self.options.get(key) == value:
            return
        self.options[key] = value
        self.save_options()
        if key in ("local_domains", "domain_presets"):
            self.apply_domains()
            names = [self.presets[k][0].split("（")[0] for k in self.options["domain_presets"] if k in self.presets]
            self.append_log(f"本地解析的域名已更新：常用软件 {('、'.join(names) or '无')}，"
                            f"自定义 {len(self.options['local_domains'])} 个，共 {len(self.all_local_domains())} 个")
        else:
            self.engine.set_options(**{key: value})
            if key == "doh":
                self.append_log(f"国内 DNS 服务改为 {dict(DOH_CHOICES).get(value, value)}")
            elif key == "vpn_adapter":
                self.append_log(f"VPN 网卡改为：{value or '自动识别'}")
            elif key == "local_adapter":
                self.append_log(f"本地网卡改为：{value or '自动识别'}")
            elif key == "vpn_keywords":
                self.append_log(f"额外的 VPN 关键字：{', '.join(value) or '无'}")

    def add_custom_domains(self, domains):
        """查找工具找到的域名加进“自定义域名”"""
        current = list(self.options["local_domains"])
        new = [d for d in domains if d not in current]
        if not new:
            return 0
        self.set_option("local_domains", current + new)
        if self.settings_window is not None:            # 设置窗口开着的话，同步显示
            box = self.settings_window.domains
            box.blockSignals(True)
            box.setPlainText("\n".join(self.options["local_domains"]))
            box.blockSignals(False)
        return len(new)

    def show_domain_finder(self):
        if self.domain_finder is None:
            self.domain_finder = DomainFinder(self)
        self.present(self.domain_finder)

    def save_options(self):
        self.cfg["options"] = self.options
        save_config(self.cfg)

    def toggle_autostart(self, checked):
        try:
            set_autostart(checked)
            self.append_log("已开启开机自动启动" if checked else "已关闭开机自动启动")
        except RuntimeError as e:
            box = self.settings_window.autostart
            self.settings_window.set_checked_quietly(box, not checked)
            QMessageBox.warning(self.settings_window, "设置开机自启失败", str(e))

    # ----- 启动 / 停止 -----

    def start_engine(self):
        self.engine.set_apps([e["match"] for e in self.entries if e["enabled"]])
        self.engine.start()
        self.update_buttons()
        self.check_system_proxy()

    def toggle(self):
        if self.paused_until is not None:             # 暂停中：立即恢复
            self.resume()
        elif self.engine.running:
            self.engine.stop()
            self.banner.hide()
        else:
            self.start_engine()
        self.cfg["running"] = self.engine.running   # 记住用户的选择
        save_config(self.cfg)
        self.update_buttons()

    def pause(self, minutes):
        """暂停分流：所有程序走 VPN，到时间自动恢复。
        不改 cfg["running"]：暂停期间退出程序，下次打开照常开始分流"""
        if not self.engine.running:
            return
        self.engine.stop()
        self.banner.hide()
        self.paused_until = time.time() + minutes * 60
        self.pause_timer.start(minutes * 60 * 1000)
        until = datetime.datetime.fromtimestamp(self.paused_until).strftime("%H:%M")
        self.append_log(f"暂停分流 {minutes} 分钟，{until} 自动恢复")
        self.set_status("paused", f"所有程序暂时走 VPN，{until} 自动恢复")
        self.update_buttons()

    def resume(self):
        if self.paused_until is None:
            return
        self.pause_timer.stop()
        self.paused_until = None
        self.append_log("暂停结束，恢复分流")
        self.start_engine()
        self.update_buttons()

    def update_buttons(self):
        running = self.engine.running
        paused = self.paused_until is not None
        self.toggle_btn.setText("立即恢复" if paused else "停止分流" if running else "开始分流")
        self.toggle_btn.setObjectName("stop" if running else "primary")
        self.toggle_btn.style().unpolish(self.toggle_btn)   # 换了 objectName，要让样式重新生效
        self.toggle_btn.style().polish(self.toggle_btn)
        self.pause_btn.setVisible(running)
        self.tray_toggle.setText("立即恢复分流" if paused else "停止分流" if running else "开始分流")
        self.tray_pause.setVisible(running)

    def check_system_proxy(self):
        def work():                                     # 要运行 PowerShell，放到后台，界面不卡
            try:
                proxy = system_proxy()
            except Exception:
                return
            if proxy:
                self.bridge.log.emit(
                    f"[注意] 系统代理已开启（{proxy}），通常是 v2rayN、Clash 等代理软件设置的。"
                    f"浏览器等跟随系统代理的程序不会直连，需要时请在代理软件里清除系统代理。")
        threading.Thread(target=work, daemon=True).start()

    # ----- 状态显示 -----

    def set_status(self, state, text):
        if self.paused_until is not None and state != "paused":
            return                                    # 暂停中：引擎停止时晚到的状态消息不显示
        prev, self.state = self.state, state
        color, title = STATUS.get(state, STATUS["stopped"])
        self.dot.setStyleSheet(f"background: {color}; border-radius: 7px;")
        self.title.setText(title)
        session = self.engine.session
        if state == "running" and session is not None:
            self.subtitle.setText(f"VPN {session.vpn_ip}   ·   本地网卡 {session.local_ip}")
        elif state == "stopped":
            self.subtitle.setText("所有程序都走 VPN")
        else:
            self.subtitle.setText(text)
        icon = status_icon(state)
        self.tray.setIcon(icon)
        self.setWindowIcon(icon)
        self.tray.setToolTip(f"{APP_NAME}：{title}")
        # 只在状态真正变化时弹通知
        if prev == "running" and state == "waiting":
            self.notify("VPN 已断开", "分流暂停，VPN 重新连上后会自动恢复。", QSystemTrayIcon.Warning)
        elif prev in ("waiting", "error") and state == "running":
            self.notify("分流已恢复", f"{title}")
        elif state == "error" and prev != "error":
            self.notify("分流出现问题", text, QSystemTrayIcon.Critical)

    # ----- 托盘、单实例 -----

    def setup_tray(self):
        self.tray = QSystemTrayIcon(status_icon("stopped"), self)
        menu = QMenu()
        menu.addAction("显示窗口", self.show_window)
        self.tray_toggle = QAction("开始分流", menu)
        self.tray_toggle.triggered.connect(self.toggle)
        menu.addAction(self.tray_toggle)
        self.tray_pause = QAction(f"暂停 {PAUSE_MINUTES} 分钟", menu)
        self.tray_pause.triggered.connect(lambda: self.pause(PAUSE_MINUTES))
        menu.addAction(self.tray_pause)
        menu.addSeparator()
        menu.addAction("退出", self.quit_app)
        self.tray_menu = menu                 # 保存引用，避免菜单被 Python 回收
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(self.on_tray_activated)
        self.tray.show()

    def on_tray_activated(self, reason):
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.show_window()

    def show_window(self):
        set_dark_titlebar(self, bool(self.dark))
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def on_instance_message(self):
        conn = self.server.nextPendingConnection()
        conn.waitForReadyRead(300)
        if bytes(conn.readAll()) == b"show":
            self.show_window()
        conn.disconnectFromServer()

    def notify(self, title, text, icon=QSystemTrayIcon.Information):
        if self.tray.isVisible():
            self.tray.showMessage(title, text, icon, 4000)

    def closeEvent(self, event):
        if self.quitting:
            event.accept()
            return
        event.ignore()                        # 点 × 不退出，只是藏到托盘
        self.hide()
        if not self.tray_hint_shown:
            self.notify(APP_NAME, "已缩到托盘，分流继续运行。右键托盘图标可以退出。")
            self.tray_hint_shown = True

    def quit_app(self):
        self.quitting = True
        self.engine.stop()                    # 注意：不改 cfg["running"]，下次打开会恢复退出前的状态
        self.tray.hide()
        self.server.close()
        QApplication.quit()

    # ----- 网卡列表、程序状态、自检（都在后台线程里做，结果通过信号送回界面） -----

    def query_network_async(self):
        if self.network_busy:
            return
        self.network_busy = True

        def work():
            try:
                data, err = query_network(), ""
            except Exception as e:
                data, err = None, str(e)
            self.network_busy = False
            self.bridge.network.emit(data, err)
        threading.Thread(target=work, daemon=True).start()

    def refresh_activity(self):
        if self.activity_busy or not self.isVisible() or not self.entries:
            return
        self.activity_busy = True
        matches = [e["match"] for e in self.entries if e["enabled"]]

        def work():
            try:
                result = self.engine.app_activity(matches)
            except Exception:
                result = {}
            self.activity_busy = False
            self.bridge.activity.emit(result)
        threading.Thread(target=work, daemon=True).start()

    def on_activity(self, result):
        self.last_activity = result
        on = self.engine.running
        for match, row in self.app_rows.items():
            enabled = next((e["enabled"] for e in self.entries if e["match"] == match), False)
            running, conns = result.get(match, (0, 0))
            row.set_activity(enabled, running, conns if on else 0, on)

    def show_self_check(self):
        if self.self_check_window is None:
            self.self_check_window = SelfCheckDialog(self)
        self.present(self.self_check_window)
        self.self_check_window.run()

    def run_self_check_async(self):
        if self.self_check_busy:
            return
        self.self_check_busy = True
        # 这些要在界面线程里先取好：后台线程不能碰界面
        options = copy.deepcopy(self.options)
        unmatched, suggest = self.preset_advice()
        enabled = [e["match"] for e in self.entries if e["enabled"]]
        titles = {m: self.describe(m)[1] for m in enabled}
        preset_titles = {k: self.preset_title(k) for k in self.presets}
        status = (self.state, self.title.text(), self.subtitle.text(), self.paused_until is not None)

        def work():
            try:
                results = self_check(self.engine, options, unmatched, suggest, enabled, titles,
                                     preset_titles, status)
            except Exception as e:
                results = [("fail", "自检本身出错", str(e))]
            self.self_check_busy = False
            self.bridge.self_check.emit(results)
        threading.Thread(target=work, daemon=True).start()

    # ----- 规则导出 / 导入 -----

    def export_rules(self, parent):
        stamp = datetime.datetime.now().strftime("%Y%m%d")
        default = os.path.join(desktop_folder(), f"SplitDirect-规则-{stamp}.json")
        path, _ = QFileDialog.getSaveFileName(parent, "导出规则", default, "规则文件 (*.json)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(rules_to_dict(self.entries, self.options), f, ensure_ascii=False, indent=2)
        except OSError as e:
            QMessageBox.warning(parent, "导出失败", str(e))
            return
        self.append_log(f"规则已导出到 {path}")
        QMessageBox.information(parent, "导出完成",
                                f"已导出 {len(self.entries)} 个程序、{len(self.options['domain_presets'])} 组常用软件、"
                                f"{len(self.options['local_domains'])} 个自定义域名：\n{path}")

    def import_rules(self, parent):
        path, _ = QFileDialog.getOpenFileName(parent, "导入规则", desktop_folder(), "规则文件 (*.json)")
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                rules = parse_rules(json.load(f))
        except (OSError, ValueError) as e:
            QMessageBox.warning(parent, "导入失败", f"无法读取规则文件：{e}")
            return
        unknown = [k for k in rules["domain_presets"] if k not in self.presets]
        presets = [k for k in rules["domain_presets"] if k in self.presets]
        missing = [a["match"] for a in rules["apps"] if "\\" in a["match"] and not os.path.exists(a["match"])]

        box = QMessageBox(parent)
        box.setWindowTitle("导入规则")
        box.setIcon(QMessageBox.Question)
        text = (f"文件里有 {len(rules['apps'])} 个程序、{len(presets)} 组常用软件、"
                f"{len(rules['local_domains'])} 个自定义域名。\n\n"
                f"合并：加到现在的规则里，已有的保留。\n替换：清空现在的规则，换成文件里的。")
        if missing:
            text += (f"\n\n注意：有 {len(missing)} 个程序在这台电脑上找不到（安装位置可能不同），"
                     f"导入后需要重新添加：\n" + "\n".join("  " + m for m in missing[:5])
                     + ("\n  ……" if len(missing) > 5 else ""))
        box.setText(text)
        merge = box.addButton("合并", QMessageBox.AcceptRole)
        replace = box.addButton("替换", QMessageBox.DestructiveRole)
        box.addButton("取消", QMessageBox.RejectRole)
        box.exec()
        chosen = box.clickedButton()
        if chosen not in (merge, replace):
            return

        if chosen is replace:
            self.entries[:] = rules["apps"]
            self.options["domain_presets"] = presets
            self.options["local_domains"] = rules["local_domains"]
            for k, v in rules["options"].items():
                self.options[k] = v
                self.engine.set_options(**{k: v})
        else:
            existing = {e["match"] for e in self.entries}
            self.entries.extend(a for a in rules["apps"] if a["match"] not in existing)
            self.options["domain_presets"] = merge_unique(self.options["domain_presets"], presets)
            self.options["local_domains"] = merge_unique(self.options["local_domains"], rules["local_domains"])
        self.save_options()
        self.apply_domains()
        self.rebuild_list()
        self.apps_changed()
        if self.settings_window is not None:
            self.settings_window.sync_from_options()
        how = "替换" if chosen is replace else "合并"
        self.append_log(f"已导入规则（{how}）：现在共 {len(self.entries)} 个程序、"
                        f"{len(self.options['domain_presets'])} 组常用软件、{len(self.options['local_domains'])} 个自定义域名")
        if unknown:
            self.append_log(f"规则里有 {len(unknown)} 组常用软件这个版本不认识，已跳过：{', '.join(unknown)}")

    # ----- 日志、统计、诊断 -----

    def show_logs(self):
        self.present(self.log_window)
        self.log_window.view.verticalScrollBar().setValue(self.log_window.view.verticalScrollBar().maximum())

    def append_log(self, text):
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_window.view.appendPlainText(f"[{now}] {text}")
        self.logger.info(text)
        if text.startswith("[注意]"):         # 需要用户留意的问题：显示在主窗口顶部
            self.banner_text.setText(text[len("[注意]"):].strip())
            self.banner.show()
        elif text.startswith("DNS 自检通过") and "DNS 自检" in self.banner_text.text():
            self.banner.hide()

    def refresh_stats(self):
        s = self.engine.stats
        if not self.engine.running:
            self.footer_stats.setText("")
            self.log_window.stats.setText("")
            return
        self.footer_stats.setText(f"本次已直连 {s['直连连接']} 个连接")
        avg = s["查询耗时ms"] / s["查询"] if s["查询"] else 0
        self.log_window.stats.setText(
            f"包 {s['包']}  改写 {s['改写']}  直连连接 {s['直连连接']}  本地解析 {s['本地解析']}  "
            f"IPv6 拦截 {s['IPv6拦截']}  事件识别 {s['事件命中']}  扫描 {s['查询']} 次({avg:.0f}ms)  "
            f"发送失败 {s['发送失败']}  出错 {s['出错']}")

    def export_diagnostics(self, parent=None):
        parent = parent or self.log_window
        if self.export_parent is not None:
            QMessageBox.information(parent, "导出诊断信息", "上一次导出还没完成，请稍候几秒。")
            return
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M")
        default = os.path.join(desktop_folder(), f"SplitDirect-诊断-{stamp}.zip")
        path, _ = QFileDialog.getSaveFileName(parent, "导出诊断信息", default, "压缩包 (*.zip)")
        if not path or self.export_parent is not None:
            return
        # 界面相关的内容在这里先取好；运行 ipconfig、route 等命令和写压缩包放到后台，界面不卡
        info = self.diagnostic_info()
        results = self.self_check_window.results if self.self_check_window is not None else []
        selfcheck = "\n".join(f"[{lv}] {t}：{d}" for lv, t, d in results) + "\n" if results else None
        self.export_parent = parent
        QApplication.setOverrideCursor(Qt.BusyCursor)

        def work():
            try:
                with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
                    try:
                        proxy = system_proxy() or "未开启"     # 可能要运行 PowerShell，放在后台
                    except Exception as e:
                        proxy = f"读取失败：{e}"
                    z.writestr("info.txt", info + f"系统代理：{proxy}\n")
                    if selfcheck:
                        z.writestr("selfcheck.txt", selfcheck)
                    z.writestr("network.txt", self.network_info())
                    if os.path.exists(CONFIG_FILE):
                        z.write(CONFIG_FILE, "config.json")
                    for name in sorted(os.listdir(LOG_DIR)):
                        z.write(os.path.join(LOG_DIR, name), f"logs/{name}")
                err = ""
            except Exception as e:
                err = str(e) or type(e).__name__
            self.bridge.export_done.emit(path, err)
        threading.Thread(target=work, daemon=True).start()

    def on_export_done(self, path, err):
        parent, self.export_parent = self.export_parent, None
        QApplication.restoreOverrideCursor()
        if err:
            QMessageBox.warning(parent, "导出失败", err)
        else:
            QMessageBox.information(
                parent, "导出完成",
                f"已导出到：\n{path}\n\n里面包含 IP 地址等网络信息，公开分享前可以先打开检查一下。")

    def diagnostic_info(self):
        def version(module):
            try:
                return __import__(module).__version__
            except Exception:
                return "未知"
        s = self.engine.session
        lines = [
            f"导出时间：{datetime.datetime.now():%Y-%m-%d %H:%M:%S}",
            f"{APP_NAME} 版本：{APP_VERSION}（{'exe' if getattr(sys, 'frozen', False) else '脚本'}）",
            f"系统：{platform.platform()}",
            f"Python：{sys.version}",
            f"pydivert：{version('pydivert')}    psutil：{version('psutil')}    PySide6：{version('PySide6')}",
            f"分流开启：{self.engine.running}    状态：{self.state}    {self.title.text()}  {self.subtitle.text()}",
            f"当前网卡：{s.ad if s else '无'}",
            f"国内 DNS：{s.doh.name if s and s.doh else '无'}    本地解析域名：{len(self.options['local_domains'])} 个",
            f"IPv6 模式：{s.v6_mode if s else '无'}",
            f"SOCKET 层：{'可用' if self.engine.sockets and self.engine.sockets.ok else '不可用或未启动'}",
            f"选项：{self.options}",
            f"名单：{self.entries}",
            f"统计：{self.engine.stats}",
        ]
        return "\n".join(lines) + "\n"

    def network_info(self):
        commands = [
            ["ipconfig", "/all"],
            ["route", "print", "-4"],
            ["route", "print", "-6"],
            ["powershell", "-NoProfile", "-Command",
             "Get-NetAdapter | Format-Table -AutoSize ifIndex, Name, InterfaceDescription, Status; "
             "Get-DnsClientServerAddress | Format-Table -AutoSize"],
        ]
        parts = []
        for cmd in commands:
            try:
                r = _run_hidden(cmd)
                parts.append(f"===== {' '.join(cmd)} =====\n{r.stdout}{r.stderr}")
            except Exception as e:
                parts.append(f"===== {' '.join(cmd)} =====\n出错：{e}")
        return "\n".join(parts)


def install_error_logging():
    """打包成无窗口的 exe 后没有控制台：标准输出指向空设备，未处理的错误写进日志文件，
    这样任何地方出错都不会让程序直接退出，事后也能在日志里查到原因"""
    for name in ("stdout", "stderr"):
        if getattr(sys, name) is None:
            setattr(sys, name, open(os.devnull, "w", encoding="utf-8"))
    logger = setup_file_log()

    def log_exception(exc_type, exc, tb):
        import traceback
        logger.error("未处理的错误：\n" + "".join(traceback.format_exception(exc_type, exc, tb)))

    sys.excepthook = log_exception
    threading.excepthook = lambda args: log_exception(args.exc_type, args.exc_value, args.exc_traceback)


def main():
    install_error_logging()
    ensure_admin()
    try:
        # 不设置的话，Windows 把本程序当成 python.exe / 默认 exe 归组，任务栏显示的是 exe 的图标
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("SplitDirect.App")
    except Exception:
        pass
    app = QApplication(sys.argv)
    app.setWindowIcon(status_icon("stopped"))
    app.setQuitOnLastWindowClosed(False)     # 窗口藏起来后程序继续在托盘里运行
    app.setStyle("Fusion")                   # 统一风格：勾选框、滚动条等才能跟着深色模式变色
    app.setStyleSheet(STYLE)
    app.setFont(QFont("Microsoft YaHei UI", 10))

    # 已经有一个在运行：叫它显示窗口，自己退出
    if tell_running_instance():
        return
    server = QLocalServer()
    QLocalServer.removeServer(SERVER_NAME)   # 清理上次异常退出留下的残留
    server.listen(SERVER_NAME)

    win = MainWindow(server)
    if "--autostart" not in sys.argv:
        win.show()
        set_dark_titlebar(win, bool(win.dark))
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
