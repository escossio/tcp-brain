"""Run the dependency-free tests used by the capture and flow modules."""
import ast
import runpy
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
    count=0
    for directory in ("capture","flow","tests"):
        for path in sorted((ROOT/directory).glob("*.py")):
            ast.parse(path.read_text(),filename=str(path))
    for path in sorted((ROOT/"tests").glob("test_*.py")):
        for name,test in sorted(runpy.run_path(str(path)).items()):
            if name.startswith("test_") and callable(test):
                test()
                count+=1
                print("PASS",name,flush=True)
    if count == 0:
        raise RuntimeError("no tests found")
    print("TOTAL",count)
if __name__=="__main__":
    main()
