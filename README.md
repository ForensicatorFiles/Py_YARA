<img width="300px" src="./images/rift.png" />

# R.I.F.T.
## Rules Initiated Forensic Triage

R.I.F.T. is a lightweight, fast, and extensible YARA-powered forensic analyzer - built for rapid triage in high pressure situations.

### To Use:
#### Recommended:
- Create a virtual environment
- Run the virtual environment
- Install requirements
- Run the program.

``` Bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python3 rift.py EXTRACTION.ZIP mobile.yara
```

Alternatively you can install opt to not use a virtual environment but that is generally not recommended. 

In addition, you can install pyinstaller and create an executable.

```
pip insall pyinstaller
pyinstaller rift.py --onefile

rift.exe EXTRACTION.ZIP mobile.yara
```


