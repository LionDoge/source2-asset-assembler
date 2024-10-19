from assetbuilder import AssetInfo, FileBlock, matchBlockIndexFromString, getFileType
import pytest
@pytest.fixture
def example_assetDataWithSameBlockNames():
    return AssetInfo(version=2, headerVersion=12, blocks=[
        FileBlock(type="kv3v4", name="RED2"),
        FileBlock(type="text", name="DATA"),
        FileBlock(type="kv3v4", name="STAT"),
        FileBlock(type="kv3v4", name="DATA"),
    ])

@pytest.mark.parametrize("blockstring,expected", [
    ("DATA1", 3),
    ("STAT", 2)
])
def test_matchBlockIndexFromString(example_assetDataWithSameBlockNames, blockstring, expected):
    assert matchBlockIndexFromString(example_assetDataWithSameBlockNames, blockstring) == expected

@pytest.mark.parametrize("invalidblockstring", [
    "DATA2",
    "DATS",
    "DATAx",
    "DATA-1"
])

def test_matchBlockIndexFromString_noMatch(example_assetDataWithSameBlockNames, invalidblockstring):
    with pytest.raises(ValueError):
        matchBlockIndexFromString(example_assetDataWithSameBlockNames, invalidblockstring)


def test_guessBinaryFileTypeFromContents(tmp_path):
    contents = b'\x00\xFF\x00\xAB\xCD\xEF' # code looks for 0x0 or 0xFF to determine binary file.
    with open(tmp_path / "file", "wb") as f:
        f.write(contents)
    with open(tmp_path / "file", "rb") as f:
        assert getFileType(f, len(contents)) == "bin"

def test_guessTextFileTypeFromContents(tmp_path):
    contents = "This is text, I promise 💗"
    with open(tmp_path / "file", "w", encoding="utf-8") as f:
        f.write(contents)
    with open(tmp_path / "file", "rb") as f:
        assert getFileType(f, len(contents)) == "text"