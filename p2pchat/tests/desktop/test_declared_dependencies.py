"""依赖声明防漂移：产品代码 import 的第三方模块必须在 requirements.txt 里声明。

由来（CI run 38191690337）：CI 装的是 `p2pchat/requirements.txt`，而 Qt 依赖当时
只写在 `requirements-lock.txt` 里。于是 `python_desktop/qt_ui.py` 的
`from PySide6 import …` 在 CI 上变成 `ModuleNotFoundError`，三个平台都在 pytest
**收集阶段**就红了。这类事故的根因不是“某个包没装”，而是“代码的 import 与依赖
声明脱节”，所以这里把它固定成一条会失败的测试。

判定规则
--------
1. 扫描产品代码（`p2pchat/*.py`、`python_desktop/`、`native/`、`backend/`）里所有
   `import X` / `from X import …` 的**顶层模块名**；
2. 丢掉标准库（`sys.stdlib_module_names`，含平台专有名字如 `fcntl`/`msvcrt`）与
   仓库自身的 `p2pchat`；
3. 剩下的必须能映射到一个**发行包名**，且该发行包名出现在 `requirements.txt`
   （`p2pchat/tools/*.py` 另外允许出现在 `platform/build-requirements.txt`）；
4. 映射方式优先用 `importlib.metadata.packages_distributions()`（真实环境里谁提供
   了这个模块），取不到时用下面显式的别名表；两者都没有就**直接失败**并提示补别名，
   不允许静默放过；
5. 确实不该进 requirements.txt 的（可选依赖、平台专有实现）只能写进
   `EXEMPT_IMPORTS`，每条都必须带非空理由；已经声明过的包再写豁免会被判为多余
   （防止用白名单盖住真正的漂移）。

自证不空转：扫描结果里必须出现已知的第三方模块（PySide6 + 四个传输/加密库），
requirements.txt 也必须解析出已知的发行包；解析器/glob 坏了会立刻失败，而不是
“零 imports → 全绿”。
"""
from __future__ import annotations

import ast
import sys
import tomllib  # noqa: F401  (kept out of the scan below; stdlib anyway)
from importlib import metadata
from pathlib import Path

PACKAGE = Path(__file__).resolve().parents[2]          # p2pchat/
REPO = PACKAGE.parent
PRODUCT_ROOT_FILES = ("__init__.py", "peer.py", "server.py")
PRODUCT_DIRS = ("python_desktop", "native", "backend")
TOOLS_DIR = "tools"

# 模块名 → 发行包名。只有在 packages_distributions() 查不到时才用，且必须写明原因；
# 目前 PySide6 是唯一一个“模块名 ≠ 发行包名”的例子。
MODULE_TO_DISTRIBUTION = {
    "PySide6": "PySide6-Essentials",   # Qt for Python：发行包名带 -Essentials 后缀
    "OpenSSL": "pyOpenSSL",            # 万一将来直接 import OpenSSL（目前没有）
}

# 允许不写进 requirements.txt 的顶层模块：每条都必须给出理由，且不得是已声明的包。
EXEMPT_IMPORTS: dict[str, str] = {
    # 目前产品代码的第三方 import 全部已在 requirements.txt 声明，因此这里是空的。
    # 例：'msvcrt': 'Windows 平台专有的标准库回退，只在 win32 分支导入',
}

# 自证用：扫描必须能看到这些模块（少一个就说明扫描/解析坏了）。
EXPECTED_THIRD_PARTY_IMPORTS = {"PySide6", "aiohttp", "aiortc", "aioquic", "cryptography"}
# 自证用：requirements.txt 必须解析出这些发行包。
EXPECTED_DECLARED_DISTRIBUTIONS = {
    "aiohttp", "aiortc", "aioquic", "cryptography", "pyside6-essentials", "pytest", "pytest-asyncio",
}


def normalise(name: str) -> str:
    """PEP 503 归一化：大小写、-/_/. 都视为等价。"""
    return name.strip().lower().replace("_", "-").replace(".", "-")


def parse_requirements(path: Path) -> set[str]:
    """requirements 文件里的发行包名（忽略注释、空行、环境标记与 extras）。"""
    declared = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        name = line.split(";", 1)[0].strip()
        for separator in ("==", ">=", "<=", "~=", "!=", ">", "<", "["):
            name = name.split(separator, 1)[0]
        if name:
            declared.add(normalise(name))
    return declared


def product_python_files() -> list[Path]:
    files = [PACKAGE / name for name in PRODUCT_ROOT_FILES if (PACKAGE / name).is_file()]
    for directory in PRODUCT_DIRS:
        files += sorted((PACKAGE / directory).rglob("*.py"))
    return [path for path in files if "__pycache__" not in path.parts]


def imported_top_level_modules(files: list[Path]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in files:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                # 相对导入（level>0）属于本包内部；绝对导入才看顶层模块名。
                names = [node.module.split(".")[0]] if node.level == 0 and node.module else []
            else:
                continue
            for name in names:
                found.setdefault(name, set()).add(str(path.relative_to(PACKAGE)))
    return found


def third_party_modules(found: dict[str, set[str]]) -> dict[str, set[str]]:
    stdlib = set(sys.stdlib_module_names) | {"__future__", "p2pchat"}
    return {name: where for name, where in found.items() if name not in stdlib}


def resolve_distribution(module: str) -> str | None:
    """模块名 → 发行包名；先查真实环境，再查显式别名表。"""
    try:
        providers = metadata.packages_distributions().get(module) or []
    except Exception:      # 环境元数据不可用时退回别名表
        providers = []
    if providers:
        return providers[0]
    alias = MODULE_TO_DISTRIBUTION.get(module)
    if alias:
        return alias
    if module in EXEMPT_IMPORTS:
        return None
    return None


def test_requirements_files_exist_and_are_parseable() -> None:
    runtime = parse_requirements(PACKAGE / "requirements.txt")
    build = parse_requirements(PACKAGE / "platform" / "build-requirements.txt")
    assert runtime, "requirements.txt 解析出了 0 个发行包，解析器或文件格式有问题"
    assert build, "platform/build-requirements.txt 解析出了 0 个发行包"
    # 自证：解析结果必须包含已知的核心发行包（防止解析器把内容吃光还“全绿”）。
    missing = EXPECTED_DECLARED_DISTRIBUTIONS - runtime
    assert not missing, f"requirements.txt 缺少这些已声明的核心依赖：{sorted(missing)}"


def test_imported_third_party_modules_are_declared() -> None:
    runtime = parse_requirements(PACKAGE / "requirements.txt")
    build = parse_requirements(PACKAGE / "platform" / "build-requirements.txt")
    third_party = third_party_modules(imported_top_level_modules(product_python_files()))

    # 自证不空转：扫描必须看到已知的第三方模块。
    missing_known = EXPECTED_THIRD_PARTY_IMPORTS - set(third_party)
    assert not missing_known, f"扫描没有发现这些已知第三方 import（扫描坏了？）：{sorted(missing_known)}"

    undeclared, unresolved = [], []
    for module, where in sorted(third_party.items()):
        if module in EXEMPT_IMPORTS:
            continue
        distribution = resolve_distribution(module)
        if distribution is None:
            unresolved.append(f"{module}（被 {sorted(where)} 导入）")
            continue
        if normalise(distribution) not in runtime:
            undeclared.append(f"{module} → {distribution}（被 {sorted(where)} 导入）")

    assert not unresolved, (
        "这些顶层模块既不在标准库里、也没有已知发行包别名，无法核对是否声明：\n  "
        + "\n  ".join(unresolved)
        + "\n请在 MODULE_TO_DISTRIBUTION 里补一条“模块 → 发行包”映射，或说明它为什么可以豁免。"
    )
    assert not undeclared, (
        "产品代码 import 了没有在 p2pchat/requirements.txt 里声明的第三方模块"
        "（CI 只装 requirements.txt，这会让收集阶段直接失败）：\n  "
        + "\n  ".join(undeclared)
        + "\n请把对应发行包加进 requirements.txt（并保持与 requirements-lock.txt 一致）。"
    )


def test_exemptions_have_reasons_and_are_not_declared_packages() -> None:
    runtime = parse_requirements(PACKAGE / "requirements.txt")
    build = parse_requirements(PACKAGE / "platform" / "build-requirements.txt")
    for module, reason in EXEMPT_IMPORTS.items():
        assert reason.strip(), f"{module} 的豁免必须写明理由"
        assert len(reason.strip()) > 8, f"{module} 的豁免理由太短，说明不了一件事"
        distribution = normalise(resolve_distribution(module) or module)
        assert distribution not in runtime and distribution not in build, (
            f"{module} 对应的 {distribution} 已经声明过了，这条豁免是多余的（可能盖住了真正的漂移）"
        )


def test_tools_imports_are_declared_in_runtime_or_build_requirements() -> None:
    """打包/冻结脚本的 import 也要有声明：要么运行时依赖，要么 build-requirements。"""
    runtime = parse_requirements(PACKAGE / "requirements.txt")
    build = parse_requirements(PACKAGE / "platform" / "build-requirements.txt")
    third_party = third_party_modules(
        imported_top_level_modules(sorted((PACKAGE / TOOLS_DIR).glob("*.py")))
    )
    assert third_party, "tools/ 下没有扫到任何第三方 import，扫描坏了？"
    for module, where in sorted(third_party.items()):
        if module in EXEMPT_IMPORTS:
            continue
        distribution = resolve_distribution(module)
        assert distribution is not None, f"{module}（被 {sorted(where)} 导入）没有发行包别名"
        assert normalise(distribution) in runtime | build, (
            f"{module} → {distribution} 既不在 requirements.txt 也不在 platform/build-requirements.txt"
        )


def test_lock_and_requirements_agree_on_the_gui_toolkit() -> None:
    """锁文件与 requirements.txt 不能对“要不要 Qt、要哪个 Qt”各说各话。"""
    runtime = parse_requirements(PACKAGE / "requirements.txt")
    lock = parse_requirements(PACKAGE / "requirements-lock.txt")
    assert "pyside6-essentials" in runtime, "requirements.txt 必须声明桌面 GUI 依赖"
    assert "pyside6-essentials" in lock, "requirements-lock.txt 必须记录已测的 GUI 版本"
    assert "shiboken6" in lock, "锁文件应记录 PySide6 的绑定运行时"
    # 锁文件里的精确版本必须落在 requirements.txt 给出的范围内。
    import re

    text = (PACKAGE / "requirements.txt").read_text(encoding="utf-8")
    locked_versions = dict(
        (normalise(line.split("==")[0]), line.split("==")[1].split()[0])
        for line in (PACKAGE / "requirements-lock.txt").read_text(encoding="utf-8").splitlines()
        if "==" in line and not line.strip().startswith("#")
    )
    assert locked_versions.get("pyside6-essentials") == "6.12.0"
    assert re.search(r"PySide6-Essentials==6\.12\.0", text), (
        "requirements.txt 应当固定到与锁文件一致的 PySide6 版本（或写明兼容范围并在此放宽断言）"
    )
