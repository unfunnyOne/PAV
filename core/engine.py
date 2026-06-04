import yara
from pathlib import Path

rules = None

class ScanResult:
    def __init__(self, filepath: Path, infected: bool, matches: list[str]):
        self.filepath = filepath
        self.infected = infected
        self.matches = matches

#Made this a separate function to be able to recompile the rules whenever we need to(after auto updating, for example)
def compileRules(rulesdir: Path = Path(__file__).parent.parent/"rules"):
    global rules

    filepaths = {}
    skipped = []

    for rule_file in rulesdir.rglob("*.yar"):
        namespace = str(rule_file.relative_to(rulesdir)).replace("\\", "_")
        #I'm compiling each file individually to see if they cause a crash, then compile only those that work
        #Some rules are using external libraries or sandboxes(like cuckoo, which was the case with /malware/MALW_AZORULT.yar)
        #I don't have them yet, so that caused an exception and resulted in a crash
        try:
            yara.compile(filepath=str(rule_file))
            filepaths[namespace] = str(rule_file)
        except Exception as e:
            skipped.append((str(rule_file), str(e)))
            continue
    try:
        rules = yara.compile(filepaths=filepaths)
    except Exception as e:
        return False, f"Fatal compilation error: {e}"

    msg = f"Rules compiled successfully. Loaded: {len(filepaths)}, skipped: {len(skipped)}"

    if skipped:
        msg += "\nSome rules were skipped due to errors."

    return True, msg


def _scanFile(filepath: Path) -> ScanResult | None:
    #I'm not using rules.match(filepath) because it breaks once a non-ASCII character appears
    try:
        with open(filepath, "rb") as f:
            data = f.read()
        matches = rules.match(data=data)

        matched_rules = [match.rule for match in matches]
        return ScanResult(filepath, len(matches) > 0, matched_rules)
    except Exception as e:
        print(f"An exception occurred during a file scan: {e}")
        return None

def scanPath(scanpath: Path, recursive: bool = True):
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
        yield _scanFile(filepath), idx, total