"""界面冒烟测试（GitHub Actions 里在真实的 Windows + PySide6 上运行，也可以本地运行）。

不碰网络和驱动：只把窗口建出来、喂几行假数据，确认不会报错、表格和筛选的结果对得上。
GUI smoke test: builds the windows on real PySide6 and feeds them fake data. No network, no driver.

    set QT_QPA_PLATFORM=offscreen
    python tools/ci_smoke.py
"""
import os
import sys
import tempfile
import time
import types

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ["APPDATA"] = tempfile.mkdtemp()                       # 不碰真实的配置文件夹
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from PySide6.QtNetwork import QLocalServer
from PySide6.QtWidgets import QApplication, QWidget

import gui

app = QApplication([])
app.setStyle("Fusion")
app.setStyleSheet(gui.STYLE)


def check(cond, text):
    print(("ok   " if cond else "FAIL ") + text, flush=True)
    if not cond:
        raise SystemExit(f"smoke test failed: {text}")


def row(port, status, name, dst, domain=None, reason="", family="IPv4", proto="tcp", idle=1.0):
    return {"proto": proto, "family": family, "port": port, "dst": dst, "dport": 443, "pid": 1,
            "status": status, "idle": idle, "direct": status == "direct", "domain": domain,
            "name": name, "path": f"c:\\apps\\{name}" if name else None, "reason": reason}


# ---------- 1. 连接列表窗口（用假的主窗口） ----------
main = QWidget()
main.bridge = gui.Bridge()
main.engine = types.SimpleNamespace(running=True)
main.requested = []
main.fetch_connections_async = lambda seconds: main.requested.append(seconds)

dlg = gui.ConnectionsDialog(main)
rows = [
    row(50001, "direct", "msedge.exe", "157.148.61.213", "www.douyin.com", "在直连名单里"),
    row(50002, "vpn", "chrome.exe", "8.8.8.8", None, "不在直连名单里，走 VPN", idle=5),
    row(50003, "blocked", "chrome.exe", "2409:8c54::1", None, "VPN 不支持 IPv6，已拦截", family="IPv6", idle=9),
    row(50004, "vpn", None, "9.9.9.9", None, "查不到连接属于哪个程序，走 VPN", proto="udp", idle=70),
]
dlg.show()
dlg.refresh()
check(main.requested == [60], "refresh asks the main window for the last 60 seconds")
main.bridge.connections.emit(rows)                              # 通过信号送进来，和真实流程一样
check(dlg.table.rowCount() == 4, "table shows all rows")
check(dlg.table.item(0, 0).text() == "直连" and dlg.table.item(0, 4).text() == "www.douyin.com", "first row cells")
check(dlg.table.item(3, 1).text() == "未知进程", "unknown process is labelled")
check("4 个连接" in dlg.summary.text() and "直连 1" in dlg.summary.text(), "summary line: " + dlg.summary.text())

dlg.kind.setCurrentIndex(1)                                     # 只看直连
check(dlg.table.rowCount() == 1, "filter: direct only")
dlg.kind.setCurrentIndex(0)
dlg.search.setText("DOUYIN")                                    # 搜域名，不分大小写
check(dlg.table.rowCount() == 1 and dlg.table.item(0, 1).text() == "msedge.exe", "search by domain")
dlg.search.setText("")
check(dlg.table.rowCount() == 4, "clearing the search restores all rows")

dlg.table.selectRow(1)                                          # 刷新后保持选中
main.bridge.connections.emit(rows)
check(dlg.selected_rows() == [1], "selection survives a refresh")

dlg.pause.setChecked(True)                                      # 暂停时不接收新数据
main.bridge.connections.emit([])
check(dlg.table.rowCount() == 4, "paused: new data ignored")
dlg.pause.setChecked(False)
dlg.copy(dlg.shown)
check(QApplication.clipboard().text().startswith("状态\t程序"), "copy puts a tab separated table on the clipboard")

main.engine.running = False
main.bridge.connections.emit([])
check(dlg.table.rowCount() == 0 and "没有运行" in dlg.summary.text(), "engine stopped: friendly message")
main.engine.running = True
main.bridge.connections.emit([])
check("最近没有" in dlg.summary.text(), "no connections: friendly message")

gui.apply_theme(True)                                           # 深色主题下重画
main.bridge.connections.emit(rows)
dlg.render()
gui.apply_theme(False)
check(dlg.table.rowCount() == 4, "re-render after theme change")
dlg.close()

# ---------- 2. 真正的主窗口 ----------
server = QLocalServer()
QLocalServer.removeServer("SplitDirect-ci-smoke")
server.listen("SplitDirect-ci-smoke")
win = gui.MainWindow(server)
win.show()
app.processEvents()
check(win.connections_window is None, "main window starts without the connections window")
win.show_connections()
check(win.connections_window is not None and win.connections_window.isVisible(), "footer 连接 opens the window")
deadline = time.time() + 5
while win.connections_busy and time.time() < deadline:         # 后台线程取数据，等它把结果送回来
    app.processEvents()
    time.sleep(0.05)
app.processEvents()
check(not win.connections_busy, "background fetch finished")
check("没有运行" in win.connections_window.summary.text(), "engine not started: " + win.connections_window.summary.text())
win.refresh_theme(force=True)
win.connections_window.close()
win.engine.stop()
print("SMOKE_OK")
sys.stdout.flush()
os._exit(0)                                                      # 不等后台线程和托盘图标，直接结束
