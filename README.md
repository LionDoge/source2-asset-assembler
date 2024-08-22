A tool to compile Source 2 assets manually.

## What's the use for this tool?
Many assets in Source 2 games still don't have a way to be compiled, or are tied to systems that are still work in progress which means that their compilers are just not shared to the public yet by Valve. 

As a good chunk of assets are text or KeyValues based it's usually not too hard to read what they do, however they can't be modified easily as they are saved in a binary format. Some of the assets include: **Pulse Graphs**, **Response Rules** or **AnimGraphs in CS2** and more.

This tool is meant to allow editing of such assets, or creating new ones from scratch, with completely custom block layout and the data inside them. The outputted files will be in already compiled format (with **_c** extension) ready to be used by the game engine.

> [!NOTE]
> This tool is still in an early development state and will not support every asset, such as models for example. The tool has been tested on a tiny subset of assets that exists, and it might generate invalid files in some cases. If that happens you're welcome to open an issue. Depending on the popularity, this tool will be devloped further to introduce more features. You are also welcome to contribute yourself!

> [!WARNING]
> This tool is meant for somewhat experienced modders. Assets created in this way have no easy way to be validated by the game, because they were not compiled by using their official compiler, which could properly verify it. This means that due to any, even tiny mistakes the asset might not work or cause crashes with very little or no explaination from the game. You're on your own here!

## Usage
Currently there are two ways of running the asset builder. First one is to use a JSON 'Schematic' file that defines the structure of the asset and the files that go with it. The second one is to use a preset.
### JSON Schema usage
This is example of a JSON file usable with this tool. It defines the valid structure for a VPULSE asset.
```json
{
    "info": {
        "headerversion": 12,
        "version": 9
    },
    "blocks": [
        {
            "type": "kv3",
            "name": "RED2",
            "file": "eventhandler_redi.kv3"
        },
        {
            "type": "kv3",
            "name": "DATA",
            "file": "eventhandler.kv3"
        }
    ]
}
```
There's a few things going on here so let's explain:

The `info` block contains the information stored at the very beginning of the asset. `headerversion` (Marked yellow) is a 2 byte integer starting at 5th byte from the start, `version` (Marked blue) is also a 2 byte integer starting at the 7th byte. Both these values, are little-endian.

![](img/asset_hex.png)

The `blocks` section contains an array of blocks that are part of the asset. Every object contains the following parameters:

- `type` - type of data stored, currently `kv3` and `text` values are supported only
- `name` - name of the block (as can be seen in Source 2 Viewer). It must be a 4 letter ASCII string.
- `file` - the source file to use for this block's data. File path is **relative** to the directory of the JSON file.

To use a schema file for compilation use the `-s` or `--schema` parameter with the relative path and file name to the schema file. Like with every method, specifying the output file with `-o` or `--output` is also required.