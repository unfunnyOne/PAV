import yara
from pathlib import Path
from typing import Generator


rules = None


class ScanResult:
    def __init__(self, filepath: Path, infected: bool, matches: list[str]):
        self.filepath = filepath
        self.infected = infected
        self.matches = matches


def compileRules(rulesdir: Path = Path(__file__).parent.parent/"rules"):
    global rules
    filepaths = {}

    try:
        for rule_file in rulesdir.rglob("*.yar"):
            namespace = str(rule_file.relative_to(rulesdir)).replace("/", "_")
            filepaths[namespace] = str(rule_file)
        rules = yara.compile(filepaths=filepaths)
    except Exception as e:
        print("An exception occurred while compiling the rules: " + str(e))


def _scanFile(filepath: Path) -> ScanResult | None:
    try:
        matches = rules.match(str(filepath))
        matched_rules = [match.rule for match in matches]
        return ScanResult(filepath, len(matches) > 0, matched_rules)
    except Exception as e:
        print(f"An exception occurred during a file scan: {e}")
        return None

def scanPath(scanpath: Path, returnnegatives: bool = False, recursive: bool = True):
    """
    Like scanPath(), but yields (result, current_index, total) tuples one by
    one so callers can show real-time progress without blocking.

    Yields: tuple[ScanResult, int, int]  →  (result, files_done, total_files)
    """
    if rules is None:
        raise RuntimeError("Rules are not compiled. Call compileRules() first.")

    try:
        if scanpath.is_file():
            files_to_scan = [scanpath]
        elif scanpath.is_dir():
            glob = scanpath.rglob("*") if recursive else scanpath.iterdir()
            files_to_scan = [f for f in glob if f.is_file()]
        else:
            raise ValueError(f"Path is neither a file nor a directory: {scanpath}")
    except Exception as e:
        print(f"Failed to collect files: {e}")
        return

    total = len(files_to_scan)

    for idx, filepath in enumerate(files_to_scan, start=1):
        result = _scanFile(filepath)
        if result is None:
            continue
        if returnnegatives or result.infected:
            yield result, idx, total
        else:
            # Still yield progress even for clean files so the bar moves
            yield ScanResult(filepath, False, []), idx, total