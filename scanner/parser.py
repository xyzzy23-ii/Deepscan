from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Iterable, Tuple

try:
    import tomli
except ImportError:
    tomli = None


class Parser:
    def parse_dependencies(self, project_path: Path) -> Dict[str, str]:
        project_path = Path(project_path)
        deps: Dict[str, str] = {}

        req_path = project_path / "requirements.txt"
        if req_path.is_file():
            deps.update(self._parse_requirements_txt(req_path))

        pyproject_path = project_path / "pyproject.toml"
        if pyproject_path.is_file():
            deps.update(self._parse_pyproject_toml(pyproject_path))

        return deps


    def _parse_requirements_txt(self, path: Path) -> Dict[str, str]:
        result: Dict[str, str] = {}

        for raw_line in self._read_lines(path):
            line = self._strip_comment(raw_line).strip()
            if not line:
                continue

            name, vers = self._split_name_and_vers(line)
            if not name:
                continue


            result[normalize_package_name(name)] = vers

        return result


    def _parse_pyproject_toml(self, path: Path) -> Dict[str, str]:
        if tomli is None:
            raise ImportError("tomli is required to parse pyproject.toml on Python 3.8+")

        data = self._read_toml(path)
        result: Dict[str, str] = {}


        project = data.get("project")
        if isinstance(project, dict):
            deps = project.get("dependencies")
            if isinstance(deps, list):
                for item in deps:
                    if not isinstance(item, str):
                        continue
                    line = self._strip_comment(item).strip()
                    if not line:
                        continue
                    name, vers = self._split_name_and_vers(line)
                    if not name:
                        continue
                    result[normalize_package_name(name)] = vers


        tool = data.get("tool")
        if isinstance(tool, dict):
            poetry = tool.get("poetry")
            if isinstance(poetry, dict):
                deps = poetry.get("dependencies")
                if isinstance(deps, dict):
                    for raw_name, raw_vers in deps.items():
                        # python = "^3.x" — это версия интерпретатора, а не PyPI-пакет
                        if not isinstance(raw_name, str) or raw_name.lower() == "python":
                            continue

                        name = raw_name.strip()
                        if not name:
                            continue

                        vers = self._poetry_value_to_vers(raw_vers)
                        result[normalize_package_name(name)] = vers

        return result

    def _poetry_value_to_vers(self, raw_vers: object) -> str:
        if raw_vers is None:
            return ""
        if isinstance(raw_vers, str):
            return raw_vers.strip()
        if isinstance(raw_vers, dict):
            v = raw_vers.get("version")
            if isinstance(v, str):
                return v.strip()
            return ""
        return ""


    def _read_lines(self, path: Path) -> Iterable[str]:
        return path.read_text(encoding="utf-8", errors="replace").splitlines()

    def _read_toml(self, path: Path) -> dict:
        raw = path.read_bytes()
        return tomli.loads(raw.decode("utf-8", errors="replace"))

    def _strip_comment(self, s: str) -> str:
        st = s.strip()
        if st.startswith("#"):
            return ""
        idx = s.find(" #")
        if idx != -1:
            return s[:idx]
        return s

    def _split_name_and_vers(self, line: str) -> Tuple[str, str]:
        line = line.strip()
        if not line:
            return "", ""

        before_marker = line.split(";", 1)[0].strip()
        if not before_marker:
            return "", ""

        m = re.match(r"^([A-Za-z0-9_.\-]+)(.*)$", before_marker)
        if not m:
            return "", ""

        name = m.group(1).strip()
        tail = m.group(2).strip()

        if tail.startswith("["):
            end = tail.find("]")
            if end != -1:
                tail = tail[end + 1 :].strip()

        return name, tail


_PEP503_NORMALIZE_RE = re.compile(r"[-_.]+")


def normalize_package_name(name: str) -> str:
    n = name.strip().lower()
    return _PEP503_NORMALIZE_RE.sub("-", n)