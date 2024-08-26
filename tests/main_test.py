from assetbuilder import readAssetFile, AssetInfo, FileBlock
import pytest

def file1AssetInfo():
    return AssetInfo(version=2, headerVersion=12, blocks=[
		FileBlock(type="kv3", name="RED2", data=None),
		FileBlock(type="text", name="DATA", data=None),
        FileBlock(type="kv3", name="STAT", data=None)
	])

def test_readAssetFile():
    assert readAssetFile("tests/files/asset1.vts_c") == file1AssetInfo()