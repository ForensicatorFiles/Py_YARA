<img width="300px" src="file_0000000075e471f588b93fbfc7078a6f.png" />

# R.I.F.T.
## Rules Initiated Forensic Triage

R.I.F.T. is a lightweight, fast, and extensible YARA-powered forensic analyzer - built for rapid triage in high pressure situations.

### To Use:
#### Recommended:
create a virtual environment, install requirements, run program.

```
python3 -m venv venv
source bin\Scripts\activate
pip install -r requirements.txt

python3 rift.py EXTRACTION.ZIP mobile.yara
```

Alternatively you can install opt to not create and use a virtual environment. 

In addition, you can install pyinstaller ans create an executable.

```
pip insall pyinstaller
pyinstaller --onefile rift.py

rift.exe EXTRACTION.ZIP mobile.yara
```


