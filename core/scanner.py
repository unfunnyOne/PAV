import engine
from pathlib import Path

engine.compileRules(Path(r"D:\PAV\rules"))
results = engine.scanPath(Path(r"D:\PAV\tests"))

for result in results:
    print(f"{str(result.filepath)}: {str(result.infected)}({str(result.matches)})")