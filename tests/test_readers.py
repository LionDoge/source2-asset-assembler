from assetbuilder import readAssetFile, AssetInfo, FileBlock, readRERLTextFile, FileFormattingError, AssetReadError
from test_writers import example_rerl_source
import pytest

@pytest.fixture
def file1AssetInfo():
    return AssetInfo(version=2, headerVersion=12, blocks=[
		FileBlock(type="kv3v4", name="RED2", data=None, dataProcessed=False),
		FileBlock(type="text", name="DATA", data=None, dataProcessed=False),
        FileBlock(type="kv3v4", name="STAT", data=None, dataProcessed=False),
	])

@pytest.fixture
def example_rerl_file():
    with open("tests/files/rerltest.txt", "r") as f:
        return f.read()

def test_readAssetFileBlockInfo(file1AssetInfo):
    assert readAssetFile("tests/files/asset1.vts_c") == file1AssetInfo

def test_readRerlData(example_rerl_file, example_rerl_source):
    assert readRERLTextFile(example_rerl_file) == example_rerl_source

def test_rerlTextRaisesErrorWithInvalidNumber():
    with pytest.raises(FileFormattingError):
        readRERLTextFile("1000a something")

def test_rerlTextRaisesErrorWithNegativeNumber():
    with pytest.raises(FileFormattingError):
        readRERLTextFile("-1 something")

def test_rerlTextRaisesErrorWithInvalidLineFormat():
    with pytest.raises(FileFormattingError):
        readRERLTextFile("0")