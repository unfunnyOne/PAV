import yara
from pathlib import Path

rules = None

# Returning just a true/false seems lazy and hard to expand in the future, so I'm going to use a class to return scan results
class ScanResult:
    def __init__(self, filepath: Path, infected: bool, matches: list[str]):
        self.filepath = filepath
        self.infected = infected
        self.matches = matches


# Decided to make this a separate function instead of compiling them at start just in case
def compileRules(rulesdir: Path):
    global rules
    filepaths = {}

    try:
        for rule_file in rulesdir.rglob("*.yar"):
            namespace = str(rule_file.relative_to(rulesdir)).replace("/", "_")
            filepaths[namespace] = str(rule_file)
        rules = yara.compile(filepaths=filepaths)
    except Exception as e:
        print("An exception occurred while compiling the rules: " + str(e))

# This shouldn't be used outside of engine module
def _scanFile(filepath: Path):
    try:
        matches = rules.match(str(filepath))
        matched_rules = [match.rule for match in matches]

        return ScanResult(filepath, len(matches) > 0, matched_rules)
    except Exception as e:
        print("An exception occurred during a file scan: " + str(e))
        return None

# This exists for ease of use
def scanPath(scanpath: Path, returnnegatives: bool = False, recursive: bool = True):
    try:
        filesToScan = []

        # Making a list of files to scan
        if scanpath.is_file():
            filesToScan = [scanpath]
        elif scanpath.is_dir():
            if recursive:
                filesToScan = [f for f in scanpath.rglob("*") if f.is_file()]
            else:
                filesToScan = [f for f in scanpath.iterdir() if f.is_file()]
        else:
            raise ValueError("Path is neither file nor directory")

        # At this point we start actually scanning
        results = []

        for file in filesToScan:
            result = _scanFile(file)

            if not returnnegatives and not result.infected:
                continue

            results.append(result)

        return results
    except Exception as e:
        print("An exception occurred during a path scan: " + str(e))
        return None