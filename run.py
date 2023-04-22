import platform
import os
import shutil

if platform.system() == "Linux":
    if os.path.isdir("proyecto1"):
        #shutil.rmtree("proyecto1")
        os.system("proyecto1/bin/python3 main.py")
    else:
        os.system("python -m venv proyecto1")
        os.system("proyecto1/bin/pip install -r requirements.txt")
        os.system("proyecto1/bin/python3 main.py")
elif platform.system() == "Windows":
    if os.path.isdir("proyecto1"):
        #shutil.rmtree("proyecto1")
        os.system(r"proyecto1\Scripts\python main.py")
    else:
        os.system("python -m venv proyecto1")
        os.system(r"proyecto1\Scripts\pip install -r requirements.txt")
        os.system(r"proyecto1\Scripts\python main.py")
elif platform.system() == "Darwin":
    if os.path.isdir("proyecto1"):
        #shutil.rmtree("proyecto1")
        os.system("proyecto1/bin/python3 main.py")
    else:
        os.system("python3 -m venv proyecto1")
        os.system("proyecto1/bin/pip install -r requirements.txt")
        os.system("proyecto1/bin/python3 main.py")
else:
	print("Sistema operativo no soportado")
