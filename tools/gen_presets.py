"""
gen_presets.py —— 重新生成程序自带的 domain_presets.py

用法：
    git clone --depth 1 https://github.com/v2fly/domain-list-community
    python tools/gen_presets.py domain-list-community/data <版本号> <日期>
    例如：python tools/gen_presets.py ../domain-list-community/data 1daade8 2026-10-30

分组和处理方法都在 preset_updater.py 里（程序运行时联网更新用的也是同一套代码）。
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import preset_updater as pu  # noqa: E402


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    data_dir, version, date = sys.argv[1:4]

    def fetch(name):
        path = os.path.join(data_dir, name)
        if not os.path.exists(path):
            return ""
        with open(path, encoding="utf-8") as f:
            return f.read()

    presets = pu.build_presets(fetch)
    lines = ['"""', 'domain_presets.py —— 程序自带的“常用软件”域名预设（由 tools/gen_presets.py 生成，请勿手工修改）', '',
             '来源：v2fly/domain-list-community（MIT License, Copyright (c) 2018-2019 V2Ray）',
             '      https://github.com/v2fly/domain-list-community',
             '处理方法见 preset_updater.py。程序运行时会检查更新，更新结果保存在 %APPDATA%\\\\SplitDirect\\\\domain_presets.json',
             '"""', '', f'VERSION = {version!r}', f'DATE = {date!r}', '', 'PRESETS = {']
    for key, (title, domains) in presets.items():
        lines.append(f'    {key!r}: ({title!r}, [')
        for i in range(0, len(domains), 4):
            lines.append('        ' + ' '.join(f'{d!r},' for d in domains[i:i + 4]))
        lines.append('    ]),')
    lines.append('}')
    out = os.path.join(ROOT, "domain_presets.py")
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"已生成 {out}：{len(presets)} 组，共 {pu.total(presets)} 个域名")


if __name__ == "__main__":
    main()
