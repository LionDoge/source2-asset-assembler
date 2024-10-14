from assetbuilder import buildRERLBlock
import pytest

@pytest.fixture
def example_rerl_source() -> list[tuple[int, str]]:
    return [
        (4028879694858690263, "materials/default/default_ao_tga_559f1ac6.vtex"),
        (3981026097612531816, "materials/default/default_metal_tga_af1d7118.vtex"),
        (16991945667032608603, "materials/default/default_normal_tga_4c6e7391.vtex")
    ]

@pytest.fixture
def example_rerl_data() -> bytes:
    data = b''
    with open("tests/files/rerlblock.bin", "rb") as f:
        data = f.read()
    return data

def test_buildRERLBlock(example_rerl_source, example_rerl_data):
    assert buildRERLBlock(example_rerl_source) == example_rerl_data