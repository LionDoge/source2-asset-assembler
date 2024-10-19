from assetbuilder import readAssetFile, AssetInfo, FileBlock, readRERLTextFile, FileFormattingError, AssetReadError
from test_writers import example_rerl_source
import pytest

@pytest.fixture
def asset1Data():
    return AssetInfo(version=2, headerVersion=12, blocks=[
		FileBlock(type="kv3v4", name="RED2", data=b'\x04\x33\x56\x4B', dataProcessed=True),
		FileBlock(type="text", name="DATA", data=b'dataaa', dataProcessed=True),
        FileBlock(type="kv3v3", name="STAT", data=b'\x03\x33\x56\x4B', dataProcessed=True),
	])

@pytest.fixture
def asset2Data():
    return AssetInfo(version=1, headerVersion=12, blocks=[
        FileBlock(type="rerl", name="RERL"),
		FileBlock(type="kv3v4", name="RED2"),
		FileBlock(type="kv3v4", name="DATA"),
        FileBlock(type="kv3v4", name="INSG"),
	])

@pytest.fixture
def example_rerl_file():
    with open("tests/files/rerltest.txt", "r") as f:
        return f.read()

def test_readAssetFileBlockInfoAndData(asset1Data):
    assert readAssetFile("tests/files/asset_minimal.vts_c", True) == asset1Data

def test_readAssetFileBlockInfoOnly(asset2Data):
    assert readAssetFile("tests/files/asset2.vmat_c", False) == asset2Data

def test_readRerlData(example_rerl_file, example_rerl_source):
    assert readRERLTextFile(example_rerl_file) == example_rerl_source

@pytest.mark.parametrize("invalidrerl", [
    "1000a something",
    "-1 something",
    "0"
])
def test_is_invalidrerl(invalidrerl):
    with pytest.raises(FileFormattingError):
        readRERLTextFile(invalidrerl)