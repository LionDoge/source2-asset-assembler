from dataclasses import field
import subprocess
import pytest
from pathlib import Path
import keyvalues3 as kv3

class Test:
    __test__ = False
    def __init__(self, launchArgs: list[str], expectedExitCode: int, compilerOutputFile: Path):
        self.launchArgs = launchArgs
        self.expectedExitCode = expectedExitCode
        self.compilerOutputFile = compilerOutputFile.absolute().as_posix()
    launchArgs: list[str]
    expectedExitCode: int
    compilerOutputFile: str

    def run(self):
        subprocess.run(["python", "assetbuilder.py", *self.launchArgs, "-o", self.compilerOutputFile], check=True)
        # add _d to the end of the file name and remove _c from the extension
        extensionPos = self.compilerOutputFile.rfind('.')
        decompiledName = self.compilerOutputFile[:extensionPos] + "_d" + self.compilerOutputFile[extensionPos:-2]
        subprocess.run(["./Decompiler", "-i", self.compilerOutputFile, '-o', decompiledName], check=True)
        return decompiledName

def test_usageWithPreset(tmp_path):
    testInfo = Test(
        ["-p", "vpulse", "-f", 
         "tests/files/samples/red2.kv3", 
         "tests/files/samples/data.kv3"],
        0,
        tmp_path / "pulsesample.vpulse_c"
    )
    decompiledName = testInfo.run()
    originalFile = kv3.read("tests/files/samples/data.kv3")
    decompiledFile = kv3.read(decompiledName)
    assert originalFile == decompiledFile

def test_usageWithStruct(tmp_path):
    testInfo = Test(
        ["-s", "tests/files/samples/struct.json"],
        0,
        tmp_path / "pulsesample.vpulse_c"
    )
    decompiledName = testInfo.run()
    originalFile = kv3.read("tests/files/samples/data.kv3")
    decompiledFile = kv3.read(decompiledName)
    assert originalFile == decompiledFile

def test_usageWithBaseFileInput(tmp_path):
    testInfo = Test(
        ["-b", "tests/files/samples/file.vpulse_c", "-f", 
         "tests/files/samples/red2.kv3", 
         "tests/files/samples/data.kv3"],
        0,
        tmp_path / "pulsesample.vpulse_c"
    )
    decompiledName = testInfo.run()
    originalFile = kv3.read("tests/files/samples/data.kv3")
    decompiledFile = kv3.read(decompiledName)
    assert originalFile == decompiledFile

def test_usageWithEdit(tmp_path):
    testInfo = Test(
        ["-e", "tests/files/samples/file.vpulse_c", "DATA", "-f"
        "tests/files/samples/edited.kv3"],
        0,
        tmp_path / "pulsesample.vpulse_c"
    )
    decompiledName = testInfo.run()
    originalFile = kv3.read("tests/files/samples/edited.kv3")
    decompiledFile = kv3.read(decompiledName)
    assert originalFile == decompiledFile

# these are more specific to just testing kv3 files
def test_kv3FlagsValidity(tmp_path):
    testInfo = Test(
        ["-p", "vpulse", "-f", 
         "tests/files/samples/red2.kv3", 
         "tests/files/samples/data_withflags.kv3"],
        0,
        tmp_path / "pulsesample.vpulse_c"
    )
    decompiledName = testInfo.run()
    originalFile = kv3.read("tests/files/samples/data_withflags.kv3")
    decompiledFile = kv3.read(decompiledName)
    assert originalFile == decompiledFile

def test_kv3BlobsValidity(tmp_path):
    testInfo = Test(
        ["-p", "vpulse", "-f", 
         "tests/files/samples/red2.kv3", 
         "tests/files/samples/data_withblobs.kv3"],
        0,
        tmp_path / "pulsesample.vpulse_c"
    )
    decompiledName = testInfo.run()
    originalFile = kv3.read("tests/files/samples/data_withblobs.kv3")
    decompiledFile = kv3.read(decompiledName)
    assert originalFile == decompiledFile

def test_kv3ArraysValidity(tmp_path):
    testInfo = Test(
        ["-p", "vpulse", "-f", 
         "tests/files/samples/red2.kv3", 
         "tests/files/samples/data_witharrays.kv3"],
        0,
        tmp_path / "pulsesample.vpulse_c"
    )
    decompiledName = testInfo.run()
    originalFile = kv3.read("tests/files/samples/data_witharrays.kv3")
    decompiledFile = kv3.read(decompiledName)
    assert originalFile == decompiledFile

def test_kv3_VKV3_version(tmp_path):
    testInfo = Test(
        ["-s", "tests/files/samples/struct_vkv3.json"],
        0,
        tmp_path / "pulsesample.vpulse_c"
    )
    decompiledName = testInfo.run()
    originalFile = kv3.read("tests/files/samples/data.kv3")
    decompiledFile = kv3.read(decompiledName)
    assert originalFile == decompiledFile