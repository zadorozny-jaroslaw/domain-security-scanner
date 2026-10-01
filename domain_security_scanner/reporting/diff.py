from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


_VOLATILE_KEYS = {"generated_at"}
_UNORDERED_LIST_KEYS = {
    "checks",
    "emails",
    "limitations",
    "scan_groups",
    "subdomains",
}
_UNORDERED_LIST_PARENTS = {
    "dns_records",
    "host_inventory",
}


class ReportDiffError(ValueError):
    """Raised when report inputs cannot be compared safely."""


@dataclass
class ReportDiff:
    added: list[dict[str, Any]] = field(default_factory=list)
    removed: list[dict[str, Any]] = field(default_factory=list)
    changed: list[dict[str, Any]] = field(default_factory=list)
    unchanged_count: int = 0

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed or self.changed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "added": self.added,
            "removed": self.removed,
            "changed": self.changed,
            "unchanged_count": self.unchanged_count,
        }


def load_report(path: str | Path) -> dict[str, Any]:
    report_path = Path(path)
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ReportDiffError(f"cannot read {report_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ReportDiffError(
            f"invalid JSON in {report_path}: line {exc.lineno}, column {exc.colno}"
        ) from exc

    _validate_report(data, report_path)
    return data


def compare_report_files(old_path: str | Path, new_path: str | Path) -> ReportDiff:
    return compare_reports(load_report(old_path), load_report(new_path))


def compare_reports(old: dict[str, Any], new: dict[str, Any]) -> ReportDiff:
    _validate_report(old, "old report")
    _validate_report(new, "new report")
    result = ReportDiff()
    _compare(old, new, (), result)
    return result


def format_diff(result: ReportDiff) -> str:
    lines: list[str] = []
    for item in result.added:
        lines.append(f"ADDED   {item['path']}: {_display(item['value'])}")
    for item in result.removed:
        lines.append(f"REMOVED {item['path']}: {_display(item['value'])}")
    for item in result.changed:
        lines.append(
            f"CHANGED {item['path']}: {_display(item['old'])} -> {_display(item['new'])}"
        )

    if not lines:
        lines.append("No meaningful differences.")
    lines.append(f"Unchanged values: {result.unchanged_count}")
    return "\n".join(lines)


def _validate_report(value: Any, source: Any) -> None:
    if not isinstance(value, dict):
        raise ReportDiffError(f"{source} is not a scanner report object")

    required = {"checks", "score"}
    if not required.issubset(value) or not any(
        key in value for key in ("domain", "target_domain")
    ):
        raise ReportDiffError(
            f"{source} does not look like a Domain Security Scanner JSON report"
        )


def _compare(old: Any, new: Any, path: tuple[str, ...], result: ReportDiff) -> None:
    if isinstance(old, dict) and isinstance(new, dict):
        old_keys = set(old) - _VOLATILE_KEYS
        new_keys = set(new) - _VOLATILE_KEYS

        for key in sorted(old_keys - new_keys):
            result.removed.append({"path": _path(path + (key,)), "value": old[key]})
        for key in sorted(new_keys - old_keys):
            result.added.append({"path": _path(path + (key,)), "value": new[key]})
        for key in sorted(old_keys & new_keys):
            _compare(old[key], new[key], path + (key,), result)
        return

    if isinstance(old, list) and isinstance(new, list):
        if _is_unordered_list(path):
            old_normalized = sorted((_canonical(item) for item in old))
            new_normalized = sorted((_canonical(item) for item in new))
            if old_normalized == new_normalized:
                result.unchanged_count += 1
            else:
                result.changed.append(
                    {"path": _path(path), "old": old, "new": new}
                )
            return

        if len(old) != len(new):
            result.changed.append({"path": _path(path), "old": old, "new": new})
            return
        for index, (old_item, new_item) in enumerate(zip(old, new)):
            _compare(old_item, new_item, path + (str(index),), result)
        return

    if old == new and type(old) is type(new):
        result.unchanged_count += 1
    else:
        result.changed.append({"path": _path(path), "old": old, "new": new})


def _is_unordered_list(path: tuple[str, ...]) -> bool:
    if not path:
        return False
    if path[-1] in _UNORDERED_LIST_KEYS:
        return True
    return any(parent in path[:-1] for parent in _UNORDERED_LIST_PARENTS)


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _path(path: tuple[str, ...]) -> str:
    if not path:
        return "$"
    result = "$"
    for part in path:
        if part.isdigit():
            result += f"[{part}]"
        else:
            result += f".{part}"
    return result


def _display(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
