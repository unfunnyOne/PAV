import engine
from pathlib import Path

engine.compileRules(Path(r"D:\PAV\rules"))
results = engine.scanPath(Path(r"D:\PAV\tests\keylogger.txt"))

for result in results:
    print()