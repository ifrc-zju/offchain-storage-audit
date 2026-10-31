from pathlib import Path
import sys,os
VENDOR=Path(__file__).resolve().parent/'vendor'
if VENDOR.exists(): sys.path.insert(0,str(VENDOR))
os.environ.setdefault('MPLCONFIGDIR',str(Path(__file__).resolve().parent/'cache/matplotlib'))
