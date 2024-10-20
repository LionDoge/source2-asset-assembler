import pytest
from pathlib import Path
import json
from assetbuilder import  parseJsonStructure, AssetInfo, FileBlock, AssetReadErrorGeneric

SAMPLE_FILES_PATH = Path("tests/files/samples")
class JsonDATA:
    def __init__(self, info, blocks):
        self.info = info
        self.blocks = blocks

@pytest.fixture
def example_assetInfo():
    return AssetInfo(version=0, headerVersion=12, blocks=[
        FileBlock(type="kv3v4", name="RED2"),
        FileBlock(type="kv3v4", name="DATA"),
    ])
# we will be slightly modifying this fixture in tests, as to not copy paste it.
@pytest.fixture
def example_structBase():
    return {
        "info": {
            "headerversion": 12,
            "version": 0
        },
        "blocks": [
            {
                "type": "kv3v4",
                "name": "RED2",
                "file": "red2.kv3"
            },
            {
                "type": "kv3v4",
                "name": "DATA",
                "file": "data.kv3"
            }
        ]
    }

def createJsonString(data):
    return json.dumps(JsonDATA(**data).__dict__)

def test_assetFromJsonStructure(example_structBase, example_assetInfo):
    result = parseJsonStructure(example_structBase, Path("tests/files/samples"))
    # intentionaly omitting the data value
    assert result.version == example_assetInfo.version
    assert result.headerVersion == example_assetInfo.headerVersion
    assert len(result.blocks) == len(example_assetInfo.blocks)
    for res_block, exp_block in zip(result.blocks, example_assetInfo.blocks):
        assert res_block.type == exp_block.type
        assert res_block.name == exp_block.name

def test_validateJsonStructure_missing_infoSection(example_structBase):
    struct = example_structBase
    del struct["info"]
    with pytest.raises(ValueError, match="missing 'info' section"):
        parseJsonStructure(struct, SAMPLE_FILES_PATH)

def test_validateJsonStructure_invalid_version(example_structBase):
    struct = example_structBase
    struct['info']['version'] = -1
    with pytest.raises(ValueError, match="invalid version number"):
        parseJsonStructure(struct, SAMPLE_FILES_PATH)

def test_validateJsonStructure_invalid_headerVersion(example_structBase):
    struct = example_structBase
    struct['info']['headerversion'] = -1
    with pytest.raises(ValueError, match="invalid headerversion number"):
        parseJsonStructure(struct, SAMPLE_FILES_PATH)

def test_validateJsonStructure_missing_blocks(example_structBase):
    struct = example_structBase
    del struct["blocks"]
    with pytest.raises(ValueError, match="missing 'blocks' section"):
        parseJsonStructure(struct, SAMPLE_FILES_PATH)


def test_validateJsonStructure_unsupportedType(example_structBase):
    struct = example_structBase
    struct['blocks'][0]['type'] = "123"
    with pytest.raises(ValueError, match="'type' must be"):
        parseJsonStructure(struct, SAMPLE_FILES_PATH)

def test_validateJsonStructure_invalid_block_name_length(example_structBase):
    struct = example_structBase
    struct['blocks'][0]['name'] = "TOOLONG"
    with pytest.raises(ValueError, match="'name' must be a 4 character string, in block no. 1"):
        parseJsonStructure(struct, SAMPLE_FILES_PATH)

def test_parseJsonStructure_file_not_found(example_structBase):
    struct = example_structBase
    struct['blocks'][0]['file'] = "idontexist.kv3"
    with pytest.raises(AssetReadErrorGeneric):
        parseJsonStructure(struct, SAMPLE_FILES_PATH)

def test_parseJsonStructure_emptyBlocksList(example_structBase):
    struct = example_structBase
    struct['blocks'] = []
    with pytest.raises(ValueError, match="empty 'blocks' list"):
        parseJsonStructure(struct, SAMPLE_FILES_PATH)

def test_parseJsonStructure_invalid_structure(example_structBase):
    struct = example_structBase
    struct['blocks'] = "not a list"
    with pytest.raises(ValueError, match="'blocks' must be a list."):
        parseJsonStructure(struct, SAMPLE_FILES_PATH)
