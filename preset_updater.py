"""
preset_updater.py —— 从社区列表（v2fly/domain-list-community）生成、更新“常用软件”的域名预设

社区列表的格式（每个文件一个列表，放在仓库的 data/ 目录下）：
    example.com            这个域名和它的所有子域名
    full:a.example.com     只有这一个域名（SplitDirect 当作普通域名处理）
    include:other          把 data/other 的内容也包含进来
    keyword: / regexp:     关键词、正则（SplitDirect 不支持，跳过）
    xxx @!cn               海外专用（不需要，跳过）
    # ...                  注释
"""

import json
import os
import time
import urllib.request

REPO = "v2fly/domain-list-community"

# 预设分组：(键, 显示名, 社区列表里的文件名)
GROUPS = [
    ("tencent", "腾讯（QQ、微信、腾讯视频、QQ 音乐）", ["tencent"]),
    ("bytedance", "字节跳动（抖音、今日头条、西瓜视频）", ["bytedance", "douyin"]),
    ("alibaba", "阿里巴巴（淘宝、支付宝、高德、优酷）", ["alibaba", "youku"]),
    ("baidu", "百度", ["baidu"]),
    ("netease", "网易（网易云音乐、邮箱、游戏）", ["netease"]),
    ("bilibili", "哔哩哔哩", ["bilibili"]),
    ("kuaishou", "快手", ["kuaishou"]),
    ("xiaohongshu", "小红书", ["xiaohongshu"]),
    ("sina", "新浪微博", ["sina"]),
    ("zhihu", "知乎", ["zhihu"]),
    ("jd", "京东", ["jd"]),
    ("meituan", "美团", ["meituan"]),
    ("pinduoduo", "拼多多", ["pinduoduo"]),
    ("iqiyi", "爱奇艺", ["iqiyi"]),
    ("mihoyo", "米哈游（原神、崩坏）", ["mihoyo"]),
    ("huawei", "华为", ["huawei"]),
    ("xiaomi", "小米", ["xiaomi"]),
    ("douyu_huya", "斗鱼、虎牙", ["douyu", "huya"]),
    ("kugou_kuwo", "酷狗、酷我", ["kugou", "kuwo"]),
    ("wps", "WPS、金山", ["wps", "kingsoft"]),
    ("csdn", "CSDN", ["csdn"]),
    ("douban", "豆瓣", ["douban"]),
    ("ctrip", "携程", ["ctrip"]),
    ("didi", "滴滴", ["didi"]),
    ("ximalaya", "喜马拉雅", ["ximalaya"]),
    ("xunlei", "迅雷", ["xunlei"]),
    ("qihoo360", "360", ["qihoo360"]),
    ("cctv", "央视", ["cctv"]),
]

# 依次尝试的下载地址；{ref} 是版本号（提交编号或 master），{name} 是文件名
MIRRORS = [
    "https://raw.githubusercontent.com/" + REPO + "/{ref}/data/{name}",
    "https://cdn.jsdelivr.net/gh/" + REPO + "@{ref}/data/{name}",
    "https://fastly.jsdelivr.net/gh/" + REPO + "@{ref}/data/{name}",
]
VERSION_API = "https://api.github.com/repos/" + REPO + "/commits/master"


# ======================================================================
# 解析和展开（打包时生成预设、运行时更新，都用这一份）
# ======================================================================

def parse_lines(text):
    """把一个列表文件拆成 (域名列表, 引用的其他文件列表)"""
    domains, includes = [], []
    for line in text.splitlines():
        line = line.split("#")[0].strip()
        if not line:
            continue
        if line.startswith("include:"):
            includes.append(line.split(":", 1)[1].split()[0])
            continue
        if line.startswith(("keyword:", "regexp:")) or "@!cn" in line:
            continue
        d = line.split()[0]
        if d.startswith(("full:", "domain:")):
            d = d.split(":", 1)[1]
        d = d.lower().strip(".")
        if "." in d:
            domains.append(d)
    return domains, includes


def expand(name, fetch, seen=None):
    """读出一个列表的所有域名，include: 引用的列表也一起展开。fetch(文件名) 返回文件内容"""
    seen = set() if seen is None else seen
    if name in seen:
        return []
    seen.add(name)
    domains, includes = parse_lines(fetch(name))
    for inc in includes:
        domains += expand(inc, fetch, seen)
    return domains


def minimal(domains):
    """去掉已经被上级域名覆盖的子域名，例如有 qq.com 就不需要 ad.qq.com"""
    s = set(domains)
    result = []
    for d in sorted(s):
        parts = d.split(".")
        if not any(".".join(parts[i:]) in s for i in range(1, len(parts) - 1)):
            result.append(d)
    return result


def build_presets(fetch):
    """按 GROUPS 生成 {键: (显示名, [域名...])}"""
    cache = {}

    def cached_fetch(name):
        if name not in cache:
            cache[name] = fetch(name)
        return cache[name]

    presets = {}
    for key, title, files in GROUPS:
        domains = []
        for f in files:
            domains += expand(f, cached_fetch)
        presets[key] = (title, minimal(domains))
    return presets


def total(presets):
    return sum(len(domains) for _, domains in presets.values())


# ======================================================================
# 联网更新
# ======================================================================

def http_get(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": "SplitDirect"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def latest_version(get=http_get):
    """返回 (版本号前 7 位, 日期)；查不到返回 (None, None)"""
    try:
        data = json.loads(get(VERSION_API))
        return data["sha"][:7], data["commit"]["committer"]["date"][:10]
    except Exception:
        return None, None


def make_fetch(ref, get=http_get, mirrors=MIRRORS):
    """返回一个按文件名下载列表的函数：一个地址失败就换下一个镜像"""
    state = {"mirror": 0}

    def fetch(name):
        errors = []
        for i in range(len(mirrors)):
            idx = (state["mirror"] + i) % len(mirrors)
            url = mirrors[idx].format(ref=ref, name=name)
            try:
                text = get(url).decode("utf-8")
                state["mirror"] = idx            # 记住能用的镜像，后面的文件先试它
                return text
            except Exception as e:
                errors.append(f"{url.split('/')[2]}: {e}")
        raise OSError(f"下载 {name} 失败：" + "；".join(errors))

    return fetch


def check_update(current_version, current_total, get=http_get, mirrors=MIRRORS):
    """检查并下载新版预设。
    返回 ("latest", None) 已是最新；("updated", 数据字典) 有新版；出错时抛出 OSError"""
    version, date = latest_version(get)
    if version is not None and version == current_version:
        return "latest", None
    presets = build_presets(make_fetch(version or "master", get, mirrors))
    new_total = total(presets)
    if new_total < current_total * 0.5:          # 少了一半以上：多半是没下载完整，不采用
        raise OSError(f"新列表只有 {new_total} 个域名（原来 {current_total} 个），可能下载不完整，未采用")
    return "updated", {
        "version": version or "master",
        "date": date or time.strftime("%Y-%m-%d"),
        "presets": {k: [title, domains] for k, (title, domains) in presets.items()},
    }


def load_saved(path):
    """读取保存的预设；没有或损坏时返回 None"""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        presets = {k: (v[0], list(v[1])) for k, v in data["presets"].items()}
        return {"version": data["version"], "date": data["date"], "presets": presets}
    except (OSError, ValueError, KeyError, TypeError, IndexError):
        return None


def save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)
    os.replace(tmp, path)                        # 先写临时文件再替换，避免写到一半损坏
