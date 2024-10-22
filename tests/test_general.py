from assetbuilder import AssetInfo, FileBlock, matchBlockIndexFromString, getFileType, tryGetGameDirectoryFromContent
import pytest
from pathlib import Path
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

def test_contentCWDOutputsToGameDir(tmp_path):
    p1 = Path(tmp_path / "content" / "citadel" / "something")
    p1.mkdir(parents=True)
    p2 = Path(tmp_path / "game" / "citadel")
    p2.mkdir(parents=True)
    assert tryGetGameDirectoryFromContent(p1) == p2 / "something"
    
def test_contentCWDWithoutValidGameDir(tmp_path):
    p1 = Path(tmp_path / "content" / "citadel" / "something")
    p1.mkdir(parents=True)
    p2 = Path(tmp_path / "game" )
    p2.mkdir(parents=True)
    assert tryGetGameDirectoryFromContent(p1) == None

def test_invalidContentCWDWithValidGameDir(tmp_path):
    p1 = Path(tmp_path / "content")
    p1.mkdir(parents=True)
    p2 = Path(tmp_path / "game" / "citadel" )
    p2.mkdir(parents=True)
    assert tryGetGameDirectoryFromContent(p1) == None

def test_randomCWDandGameDir(tmp_path):
    p1 = Path(tmp_path / "something")
    p1.mkdir(parents=True)
    p2 = Path(tmp_path / "somethingelse" / "output" )
    p2.mkdir(parents=True)
    assert tryGetGameDirectoryFromContent(p1) == None