import yara
from pathlib import Path

#Remove this later
import re

compiled_rules = {}

#TODO: Make an actual dataset based on the ratio of detections and false positives for each rule
#Right now I'll just fill it with 1's
ruleweights = {}

#Remove this too, once we have an actual weights dataset
def extract_rule_names(rule_file: Path):
    text = rule_file.read_text(encoding="utf-8", errors="ignore")
    return re.findall(r"\brule\s+([a-zA-Z0-9_]+)", text)

class ScanResult:
    def __init__(self, filepath: Path, infected: bool, matches: list[str], riskscore: int):
        self.filepath = filepath
        self.infected = infected
        self.matches = matches
        self.riskscore = riskscore

#Made this a separate function to be able to recompile the rules whenever we need to(after auto updating, for example)
def compileRules(rulesdir: Path = Path(__file__).parent.parent / "rules"):
    global compiled_rules

    compiled_rules.clear()

    filepaths = {}
    skipped = []

    #Categorizing and making sure that all of our rules are actually compiling
    for rule_file in rulesdir.rglob("*.yar"):
        try:
            #Checking if the rule compiles before adding it to the list
            rule = yara.compile(filepath=str(rule_file))

            relative = rule_file.relative_to(rulesdir)
            # This returns the directory name of our category folder(signatures/heuristics as of 05.06)
            category = relative.parts[0]

            # This is here to prevent duplicates from overriding each other
            namespace = str(relative).replace("\\", "_")
            #TODO: Remove this and load an existing dataset instead
            for r in extract_rule_names(rule_file):
                print(f"Setting weight for: {namespace}::{r}")
                ruleweights[f"{namespace}::{r}"] = 1

            if category not in filepaths:
                filepaths[category] = {}
            #Rule successfully compiles, so we add it to the final list for compilation
            filepaths[category][namespace] = str(rule_file)

        except Exception as e:
            #Saving this for debug
            skipped.append((str(rule_file), str(e)))
            continue

    #Now we're actually compiling the rules
    try:
        for category in filepaths:
            compiled_rules[category] = yara.compile(filepaths=filepaths[category])
    except Exception as e:
        return False, f"Couldn't compile the rules: {e}"

    loaded_rules = sum(len(filepaths) for filepaths in filepaths.values())
    msg = (
        f"Rules compiled successfully.\n"
        f"Categories loaded: {len(filepaths)}\n"
        f"Rules loaded: {loaded_rules}\n"
        f"Rules skipped: {len(skipped)}"
    )

    if not compiled_rules:
        return False, ("No rule categories could be compiled.\n" + msg)

    return True, msg


def _scanFile(filepath: Path) -> ScanResult | None:
    #I'm using rules.match(data) instead of rules.match(filepath) because it breaks once a non-ASCII character appears
    try:
        #First, we check for known signatures
        with open(filepath, "rb") as f:
            data = f.read()
        matches = compiled_rules["signatures"].match(data=data)

        if matches:
            matched_rules = [match.rule for match in matches]
            return ScanResult(filepath, True, matched_rules, 100)

        #Now, since our file doesn't match any known signatures, we'll run a heuristic analysis
        matches = compiled_rules["heuristics"].match(data=data)

        if matches:
            score = 0
            matched_rules = [match.rule for match in matches]

            for match in matches:
                score += ruleweights[f"{match.namespace}::{match.rule}"]

            #TODO: Don't forget to remove that "score>3" and replace it with something that actually makes sense
            return ScanResult(filepath, score>3, matched_rules, score)
        else:
            return ScanResult(filepath, False, [], 0)

    except Exception as e:
        print(f"An exception occurred during a file scan: {e}")
        return None

def scanPath(scanpath: Path, recursive: bool = True):
    if not compiled_rules:
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