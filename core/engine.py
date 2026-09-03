import os
from pathlib import Path
import tomllib

os.environ["LIBARCHIVE"] = str(Path(__file__).resolve().parent.parent/"bin"/"libarchive-13.dll")

# For debugging and stuff
import warnings

# Base
import yara

# Archives
import libarchive

# Remove this later
import re

# Everything is stored in the config file! Don't forget to loadConfig()!
# Settings for regular scanning. Don't wanna load the entire C: partition into the RAM, right?
MAX_FILE_SIZE = 0

# Settings for archive scanning. We don't want to unpack zip bombs, do we?
MAX_ARCHIVE_DEPTH = 0
MAX_ARCHIVE_FILES = 0
MAX_ARCHIVE_UNPACKED_SIZE = 0

# TODO: Make an actual dataset based on the ratio of detections and false positives for each rule
# Right now I'll just fill it with 1's
rule_weights = {}

compiled_rules = {}

class ScanResult:
    def __init__(self, filepath: Path, infected: bool, matches: list[str], riskscore: int):
        self.filepath = filepath
        self.infected = infected
        self.matches = matches
        self.riskscore = riskscore

# I could've used a dictionary instead, but I think it looks cleaner this way
class FileData:
    def __init__(self, filepath: Path, data: bytes):
        self.filepath = filepath
        self.data = data

# Remove this too, once we have an actual weights dataset
def _extractRuleNames(rule_file: Path):
    text = rule_file.read_text(encoding="utf-8", errors="ignore")
    return re.findall(r"\brule\s+([a-zA-Z0-9_]+)", text)

# Made this a separate function to be able to recompile the rules whenever we need to(after auto updating, for example)
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
            for r in _extractRuleNames(rule_file):
                rule_weights[f"{namespace}::{r}"] = 1

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

# The same as compileRules(), made this a function to change settings while running
def loadConfig() -> tuple[bool, str]:
    print("Starting loadConfig()")
    global MAX_FILE_SIZE, MAX_ARCHIVE_DEPTH, MAX_ARCHIVE_UNPACKED_SIZE, MAX_ARCHIVE_FILES

    try:
        config_file = Path(__file__).parent.parent/"config/engine_config.toml"
        with config_file.open("rb") as f:
            config = tomllib.load(f)

        # Validation
        if config["scan"]["MAX_FILE_SIZE"] is None or config["scan"]["MAX_FILE_SIZE"] < 0: raise ValueError("Invalid MAX_FILE_SIZE")
        if config["archive"]["MAX_ARCHIVE_DEPTH"] is None or config["archive"]["MAX_ARCHIVE_DEPTH"] < 0: raise ValueError("Invalid MAX_ARCHIVE_DEPTH")
        if config["archive"]["MAX_ARCHIVE_FILES"] is None or config["archive"]["MAX_ARCHIVE_FILES"] < 0: raise ValueError("Invalid MAX_ARCHIVE_FILES")
        if config["archive"]["MAX_ARCHIVE_UNPACKED_SIZE"] is None or config["archive"]["MAX_ARCHIVE_UNPACKED_SIZE"] < 0: raise ValueError("Invalid MAX_ARCHIVE_UNPACKED_SIZE")

        # Assigning
        MAX_FILE_SIZE = config["scan"]["MAX_FILE_SIZE"]
        MAX_ARCHIVE_DEPTH = config["archive"]["MAX_ARCHIVE_DEPTH"]
        MAX_ARCHIVE_FILES = config["archive"]["MAX_ARCHIVE_FILES"]
        MAX_ARCHIVE_UNPACKED_SIZE = config["archive"]["MAX_ARCHIVE_UNPACKED_SIZE"]
    except Exception as e:
        warnings.warn(f"An error occured while loading config:\n{e}", Warning, 1, "Config")
        return False, f"An error occured while loading config: {e}"
    return True, "Config successfully loaded"

# Since we're already reading bytes, might as well use that
def _isArchive(data: bytes) -> bool:
    return (
        data.startswith(b"PK") or          # zip
        data.startswith(b"Rar!\x1A") or    # rar
        data.startswith(b"7z\xBC\xAF") or   # 7z
        data.startswith(b"\x1F\x8B") or     # gz
        (len(data) > 262 and data[257:262] == b"ustar")  # tar
    )

# This function is recursive(to read nested archives)
# God, that took a long time to make
def _collectFromArchive(data: bytes, total_size: int = 0, file_count: int = 0, depth: int = 0, prefix: str = "") -> tuple[list[FileData], int, int]:
    files = []

    with libarchive.memory_reader(data) as archive:
        for entry in archive:
            entry_data = bytearray()

            # get_blocks() is a generator, so we're gonna use it to read the file block by block
            # so we don't load a 10GB file into the RAM before checking its size
            for block in entry.get_blocks():
                entry_data.extend(block)
                if len(entry_data) > MAX_FILE_SIZE:
                    warnings.warn(f"Skipped a file exceeding {MAX_FILE_SIZE} bytes in {prefix}", Warning, 1, f"{prefix}")
                    break
            else:   # if loop completed without a break
                entry_data = bytes(entry_data)
                total_size += len(entry_data)
                file_count += 1

                if total_size > MAX_ARCHIVE_UNPACKED_SIZE or file_count >= MAX_ARCHIVE_FILES:
                    warnings.warn(f"Unpacked archive {prefix} exceeded max size: {MAX_ARCHIVE_UNPACKED_SIZE}", Warning, 1, f"{prefix}")
                    break

                new_prefix = f"{prefix}/{entry.pathname}"
                if _isArchive(entry_data):
                    if depth < MAX_ARCHIVE_DEPTH:
                        try:
                            # If it's a nested archive, we start recursion
                            nested_files, total_size, file_count = _collectFromArchive(
                                data=entry_data,
                                total_size=total_size,
                                file_count=file_count,
                                depth=depth + 1,
                                prefix=new_prefix
                            )
                            files.extend(nested_files)
                        except Exception as e:
                            print(f"Nested archive error: {e}")
                    else:
                        warnings.warn(f"Reached max recursion depth at {prefix}!", Warning, 1, f"{prefix}")
                else:
                    files.append(FileData(Path(new_prefix), entry_data))
    return files, total_size, file_count

def _scanFile(filedata: FileData) -> ScanResult | None:
    # I'm using rules.match(data) instead of rules.match(filepath) because it breaks once a non-ASCII character appears
    try:
        # First, we check for known signatures
        matches = compiled_rules["signatures"].match(data=filedata.data)

        if matches:
            matched_rules = [match.rule for match in matches]
            return ScanResult(filedata.filepath, True, matched_rules, 100)

        # Now, since our file doesn't match any known signatures, we'll run a heuristic analysis
        matches = compiled_rules["heuristics"].match(data=filedata.data)

        if matches:
            score = 0
            matched_rules = [match.rule for match in matches]

            for match in matches:
                score += rule_weights[f"{match.namespace}::{match.rule}"]

            #TODO: Don't forget to remove that "score>3" and replace it with something that actually makes sense
            return ScanResult(filedata.filepath, score>3, matched_rules, score)
        else:
            return ScanResult(filedata.filepath, False, [], 0)

    except Exception as e:
        print(f"An exception occurred during a file scan: {e}")
        return None

def scanPath(scanpath: Path, recursive: bool = True) -> (ScanResult, int, int):
    if not compiled_rules:
        raise RuntimeError("Rules are not compiled. Call compileRules() first.")

    if scanpath.is_file():
        data = scanpath.read_bytes()
        yield _scanFile(FileData(scanpath,data)), 1, 1
    elif scanpath.is_dir():
        # Doing this because I don't want to load all the Path elements into the memory
        # It does walk the paths twice, sure, but I don't have better ideas
        if recursive:
            total = sum(1 for f in scanpath.rglob("*"))
            glob = scanpath.rglob("*")
        else:
            total = sum(1 for f in scanpath.iterdir())
            glob = scanpath.iterdir()

        for idx, f in enumerate(glob, start=1):
            try:
                # No point in scanning directory objects, right?
                if f.is_file():
                    if f.stat().st_size > MAX_FILE_SIZE:
                        warnings.warn(f"Skipping a file exceeding max size: {f.name}")
                        continue
                    data = f.read_bytes()

                    # Read the archive contents if it's an archive
                    if _isArchive(data):
                        extracted = _collectFromArchive(data=data, prefix=str(f))[0] #"[0]" because it returns a tuple
                        for filedata in extracted:
                            yield _scanFile(filedata), idx, total
                    else:
                        yield _scanFile(FileData(f, data)), idx, total
            except Exception as e:
                print(f"Exception while scanning a directory: {e}. Skipping")
                continue

    # Not sure if that's even possible, but I'll add this just in case
    else:
        raise ValueError(f"Path is neither a file nor a directory: {scanpath}")