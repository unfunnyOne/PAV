import requests
import json

import os
import tempfile
import shutil

from pathlib import Path
from datetime import datetime

os.environ["LIBARCHIVE"] = str(Path(__file__).resolve().parent.parent/"bin"/"libarchive-13.dll")
import libarchive

class Source:
    def __init__(self, name: str, link: str, version_url: str):
        self.name = name
        self.link = link
        self.version_url = version_url

SOURCES_FILE = Path(__file__).parent.parent / "config/rule_sources.json"
VERSIONS_FILE = Path(__file__).parent.parent / "config/rule_versions.json"

def _loadSources():
    with SOURCES_FILE.open("r", encoding="utf-8") as f:
        data = json.load(f)
        return [
            Source(
                name=source["name"],
                link=source["link"],
                version_url=source["version_url"]
            )
            for source in data
        ]

def _loadVersions() -> dict[str, str]:
    if not VERSIONS_FILE.exists() or VERSIONS_FILE.stat().st_size == 0:
        return {}

    with VERSIONS_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)

def _saveVersions(versions: dict[str, str]):
    with VERSIONS_FILE.open("w", encoding="utf-8") as f:
        json.dump(versions, f, indent=2)

def _downloadRules(url: str, destination: Path) -> Path:
    response = requests.get(url, stream=True, timeout=30)
    response.raise_for_status()

    with destination.open("wb") as f:
        for chunk in response.iter_content(chunk_size=1024 * 1024):
            if chunk:
                f.write(chunk)
    return destination

def _unpackRules(archive_path: Path, destination: Path):
    destination.mkdir(parents=True, exist_ok=True)

    with libarchive.file_reader(str(archive_path)) as archive:
        for entry in archive:
            output_path = destination / entry.pathname

            if entry.isdir:
                output_path.mkdir(parents=True, exist_ok=True)
                continue

            output_path.parent.mkdir(parents=True, exist_ok=True)

            with output_path.open("wb") as f:
                for block in entry.get_blocks():
                    f.write(block)

def updateRules():
    # First, we gotta determine which rules need updating. Load sources and versions
    sources = _loadSources()
    versions = _loadVersions()

    to_update = []
    for source in sources:
        try:
            release_data = requests.get(source.version_url, timeout=10)
            release_data.raise_for_status()
            if versions.get(source.name) is None or datetime.fromisoformat(release_data.json()["published_at"].replace("Z", "+00:00")) > datetime.fromisoformat(versions[source.name].replace("Z", "+00:00")):
                to_update.append(source)
                versions[source.name] = release_data.json()["published_at"]
        except Exception as e:
            print(f"An exception happened when updating rules: {e}")

    # Now that we know which rules should be updated, let's start downloading
    # Notice how I'm using a temp directory! I feel so smart about it lmao
    with tempfile.TemporaryDirectory() as tempdir:
        temp_path = Path(tempdir)
        try:
            for source in to_update:
                archive_path = _downloadRules(source.link, temp_path/f"rules_{source.name}.zip")

                destination_path = Path(__file__).resolve().parent.parent / "rules" / source.name

                # Delete the old directory
                if destination_path.exists():
                    shutil.rmtree(destination_path)

                _unpackRules(archive_path, destination_path)
                # Now, one last thing: update the versions
                _saveVersions(versions)
        except Exception as e:
            print(f"An exception occured when downloading rules: {e}")

    return True, f"Rules updated: {len(to_update)}"