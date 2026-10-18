import re
import shutil
import subprocess
from pathlib import Path
from app.config import TSHARK_PATH

def find_tshark() -> str|None:
    if TSHARK_PATH:return TSHARK_PATH if Path(TSHARK_PATH).is_file() else None
    path=shutil.which("tshark")
    if path:return path
    fallback=Path(r"C:\Program Files\Wireshark\tshark.exe")
    return str(fallback) if fallback.is_file() else None

def tshark_version(path: str|None) -> str|None:
    if not path:return None
    try:
        p=subprocess.run([path,"-v"],capture_output=True,text=True,timeout=5,check=False)
        if p.returncode:return None
        line=(p.stdout or p.stderr).splitlines()[0]
        m=re.search(r"Wireshark\s+\S+",line,re.I)
        return m.group(0) if m else line[:200]
    except (OSError,subprocess.SubprocessError,IndexError):return None
