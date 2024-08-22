import subprocess
import sys
import os
from pathlib import Path
DECOMP_PATH = Path("./")
COMPILE_FILES_PRESET = ["examples/pulse/pulsesample_redi.kv3", "examples/pulse/pulsesample.vpulse"]
ORIGINAL_FILE = "examples/pulse/pulsesample.vpulse"
COMPILER_OUTPUT_FILE_NAME = "pulsesample.vpulse_c"

decompilerBinary = (DECOMP_PATH / "Decompiler").resolve()
os.chmod(decompilerBinary, 0o775) # rwx-rwx-r-x
subprocess.run(["python", "assetbuilder.py", "-p", "vpulse", "-f", 
                *COMPILE_FILES_PRESET,
                  "-o", COMPILER_OUTPUT_FILE_NAME], check=True) # will exit with err code on failure
origFile = open(ORIGINAL_FILE, "r", encoding="utf-8")

extensionPos = COMPILER_OUTPUT_FILE_NAME.rfind('.')
# add _d to the end of the file name and remove _c from the extension
decompiledName = COMPILER_OUTPUT_FILE_NAME[:extensionPos] + "_d" + COMPILER_OUTPUT_FILE_NAME[extensionPos:-2]

subprocess.run([decompilerBinary, "-i", COMPILER_OUTPUT_FILE_NAME, '-o', decompiledName], check=True) # will exit with err code on failure
decompiledFile = open(decompiledName, "r", encoding="utf-8")

currLine = 0
exitCode = 0
origFileEnded = False
decompFileEnded = False
while True:
    origLine = origFile.readline()
    if not origLine: # Empty line will always result in \n whereas EOF will result in empty string
        origFileEnded = True
    origLineStrip = origLine.strip()
    while len(origLineStrip) == 0 and origFileEnded == False: # skip empty lines
        origLineStrip = origFile.readline().strip()
    decompLine = decompiledFile.readline()
    if not decompLine:
        decompFileEnded = True
    decompLineStrip = decompLine.strip()
    while len(decompLineStrip) == 0 and decompFileEnded == False: # skip empty lines
        decompLineStrip = decompiledFile.readline().strip()
    if origFileEnded and decompFileEnded:
        print("Decompiled file matches original file")
        break
    if origLineStrip != decompLineStrip:
        print("Decompiled file does not match original file")
        exitCode = 1
        break

sys.exit(exitCode)