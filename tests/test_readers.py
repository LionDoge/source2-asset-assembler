from assetbuilder import readAssetFile, AssetInfo, FileBlock
import pytest

@pytest.fixture
def file1AssetInfo():
    return AssetInfo(version=2, headerVersion=12, blocks=[
		FileBlock(type="kv3v4", name="RED2", data=None, dataProcessed=False),
		FileBlock(type="text", name="DATA", data=None, dataProcessed=False),
        FileBlock(type="kv3v4", name="STAT", data=None, dataProcessed=False),
	])

def test_readAssetFileBlockInfo(file1AssetInfo):
    assert readAssetFile("tests/files/asset1.vts_c") == file1AssetInfo