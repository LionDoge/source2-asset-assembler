import sys
import struct
import json
from enum import IntEnum
from typing import Optional
from dataclasses import dataclass, field
from pathlib import Path
from uuid import UUID
import argparse
import keyvalues3 as kv3
import lz4.block
import os
from copy import deepcopy

class KVType(IntEnum):
	STRING_MULTI = 0,
	NULL = 1,
	BOOLEAN = 2,
	INT64 = 3,
	UINT64 = 4,
	DOUBLE = 5,
	STRING = 6,
	BINARY_BLOB = 7,
	ARRAY = 8, # generic array of mixed types. Every element has assigned type in types list.
	OBJECT = 9, # dict in Python
	ARRAY_TYPED = 10, # typed array with 4 byte length saved in data section
	INT32 = 11,
	UINT32 = 12,
	BOOLEAN_TRUE = 13,
	BOOLEAN_FALSE = 14,
	INT64_ZERO = 15,
	INT64_ONE = 16,
	DOUBLE_ZERO = 17,
	DOUBLE_ONE = 18,
	FLOAT = 19,
	INT16 = 20,
	UINT16 = 21,
	UNKNOWN_22 = 22,
	INT32_AS_BYTE = 23,
	ARRAY_TYPE_BYTE_LENGTH = 24 # typed array with length < 256. Saved as 1 byte in binaryBytes section

@dataclass
class FileHeaderInfo:
	size: int = 0
	offset: int = 0

@dataclass
class FileBlock:
	data: any
	dataProcessed: bool
	type: str
	name: str

@dataclass
class KVBaseData:
	strings: list[str] = field(default_factory=list)
	types: list[bytes] = field(default_factory=list)
	binaryBytes: list[bytes] = field(default_factory=list) # this list sits at almost the beginning of kv data.
	doubles: list[float] = field(default_factory=list)
	countOfIntegers: int = 0
	countOfEightByteValues: int = 0
	stringAndTypesBufferSize: int = 0
	countOfStrings: int = 0
	countOfBinaryBytes: int = 0

# small function to return the amount of bytes needed to add for alignment so that: fileSize % mod == 0
def alignToBytes(mod: int, fileSize: int) -> tuple[bytes, int]:
	bytesAmount = (-fileSize) % mod
	return (b'\x00' * bytesAmount, bytesAmount)

def buildFileData(version: int, headerVersion: int, blocks: list[FileBlock]) -> bytes:
	fileSize = 0 # byte 0 (4 bytes)
	printDebug(f"version: {version}\nheader version: {headerVersion}\nblock count: {len(blocks)}\n")
	headerVersion = headerVersion.to_bytes(2, 'little') # byte 4 (2 bytes)
	version = version.to_bytes(2, 'little') # byte 6 (2 bytes)

	blockOffset = 8 # where the block info starts, should really always be the same.
	blockOffset = blockOffset.to_bytes(4, 'little') # byte 12 (4 bytes)
	blockCount = len(blocks) # amount of blocks
	blockCount = blockCount.to_bytes(4, 'little') # byte 16 (4 bytes)

	combinedBlockHeaderData = b''
	assetHeaderSize = (16 + 12*len(blocks)) # 16 is the size of the header, 12 is the size of each block header (name, offset, size)
	headerPadAmount = -assetHeaderSize % 16
	assetHeaderSize += headerPadAmount # the data is also padded with 0s to align to 16 bytes.

	fileSize = assetHeaderSize

	# the offsets are relative to where they are placed in the file.
	# We should know the first one's value, since the first block of data is right after the header.
	# first offset: 8 is the offset to another block info, every block info is 12 bytes long.
	currentOffset = 8 + ((len(blocks) - 1) * 12) + headerPadAmount
	dataBlocks = []
	for idx, block in enumerate(blocks):
		printDebug(f"Processing block {idx+1} (name: {block.name} type: {block.type})")
		blockData: bytes = b''
		dataSize = 0
		usingExistingData = True
		blockHeaderInfo = FileHeaderInfo()
		if block.dataProcessed == False:
			usingExistingData = False
			if block.type == "kv3":
				blockUUID: UUID = block.data.format.version
				blockData = buildKVBlock(block.data, blockUUID.bytes_le, blockHeaderInfo, visualName=block.name)
			elif block.type == "text":
				blockData = buildTextBlock(block.data, blockHeaderInfo, visualName=block.name)
			else:
				usingExistingData = True
				blockData = block.data
			block.dataProcessed = True
		else:
			blockData = block.data

		if usingExistingData == False:
			dataSize = blockHeaderInfo.size
		else:
			dataSize = len(blockData)
		# fill with 0 bytes to align to 16 bytes
		if idx != len(blocks)-1:
			alignBytes = alignToBytes(16, fileSize + dataSize)
			blockData += alignBytes[0]
			fileSize += alignBytes[1]
			additionalOffset = alignBytes[1]
		fileSize += dataSize
		dataBlocks.append(blockData)

		combinedBlockHeaderData += b''.join([block.name.encode('ascii'), currentOffset.to_bytes(4, 'little'), dataSize.to_bytes(4, 'little')])
		currentOffset += dataSize + additionalOffset
		currentOffset -= 12 # -12 because we need to account for where the next offset value is placed.
	
	binData = b''.join([fileSize.to_bytes(4, 'little'), headerVersion, version, blockOffset, blockCount, # FILE HEADER (16 bytes)
				   combinedBlockHeaderData, (b'\x00'*headerPadAmount)]) # HEADER DATA FOR BLOCKS + PADDING
	for block in dataBlocks:
		binData += block # DATA BLOCKS
	printDebug(f"Final file size: {fileSize} bytes")
	return binData

KV3_FORMAT_GUID = b'\x7C\x16\x12\x74\xE9\x06\x98\x46\xAF\xF2\xE6\x3E\xB5\x90\x37\xE7'

def buildTextBlock(textData, textHeaderInfo, visualName: str = "unnamed block") -> bytes:
	textHeaderInfo.size = len(textData)
	printDebug(f"Stats for {visualName} block")
	printDebug(f"Text size: {textHeaderInfo.size}\n")
	return textData

def buildKVBlock(block_data, guid, header_info, visualName: str = "unnamed block") -> bytes:
	# The definitions at the beginning here are useless in terms of the functionality
	# However I decided to keep them here in approperiate order to make it easier to understand the structure of the KV3 data.
	headerData = KVBaseData()
	kv3ver = b'\x04' # For now we only support version 4 of KV3
	constantsAfterGUID = b'\x01\x00\x00\x00\x00\x00\x00\x40' # contains compressionMethod, compressionDictionaryID and compressionFrameSize.
	headerData.countOfBinaryBytes = 0
	headerData.countOfIntegers = 1 # All of the actual kv Data plus countOfStrings, which is always here, so we start from one.
	headerData.countOfEightByteValues = 0
	headerData.stringAndTypesBufferSize = 0 # length of strings + length of types combined
	preallocValues = b'\xFF\xFF\xFF\xFF' #! Apparently these are used to preallocate something, for safety I'll put in FFFF, it seems to be working fine so far.
	headerData.uncompressedSize = 0 # decompressed kv3 block size
	headerData.compressedSize = 0 # compressed kv3 block size
	blockCount: int = 0 # always the same
	blockTotalSize: int = 0 # always the same
	unknowns = b'\x00' * 8 # Appears to always be the same - can ignore.
	# after all this we finally have actual kv data...

	# ------ DATA LATER IS LZ4 COMPRESSED! -------
	headerData.binaryBytes = [] # length is count of binary bytes
	headerData.countOfStrings = 0
	# after countOfStrings we have data about the structure, mostly because the data is actually just integers that references stuff.
	kvData = b''
	headerData.doubles = []
	doublesBytes = b"" # transformed for appending
	# after list of doubles we have a list of null terminated strings:
	headerData.strings = [] # add strings here as we go parsing the kv text data.
	stringsBytesList: list[bytes] = [] # transformed for appending
	# after strings there is list of types, each one is one byte, the length is amount of types that we get from substracting string length from 'stringAndTypesLength'
	headerData.types = []
	# this comes after types list.
	blockEndTrailer: int = 4293844224 # this should always be this value.
	# write the binary kv data, and output all stats into headerData
	kvData = buildKVStructure(block_data.value, headerData, False)
	headerData.countOfStrings = len(headerData.strings)
	headerData.countOfBinaryBytes = len(headerData.binaryBytes)
	# null terminate all strings
	for s in headerData.strings:
		stringsBytesList.append(bytes(s, "ascii") + b'\x00')
	headerData.stringAndTypesBufferSize = len(headerData.types) + len(b''.join(stringsBytesList))
	headerData.binaryBytes = bytes(headerData.binaryBytes)
	headerData.binaryBytes += b'\x00' * (-len(headerData.binaryBytes) % 4) # align to 4 bytes
	for v in headerData.doubles:
		doublesBytes += struct.pack("<d", v) # little-endian eight bytes
	infoSectionLen = len(kvData) + 4 + len(headerData.binaryBytes)
	kvData += b'\x00' * (-infoSectionLen % 8) # make sure that ints align to 8 bytes, as we have doubles next!

	blockDataUncompressed = b''.join([headerData.binaryBytes, headerData.countOfStrings.to_bytes(4, "little"),
								  	bytes(kvData), doublesBytes, b''.join(stringsBytesList), bytes(headerData.types),
									blockEndTrailer.to_bytes(4, "little")])
	# values tested based on 2v2_enable.vpulse_c
	blockDataCompressed = lz4.block.compress(blockDataUncompressed, mode='high_compression',compression=11,store_size=False) 
	# we need to note both sizes.
	uncompressedSize = len(blockDataUncompressed).to_bytes(4, "little")
	compressedSize = len(blockDataCompressed).to_bytes(4, "little")
	blockDataBase = b''.join([kv3ver, "3VK".encode('ascii'), guid, constantsAfterGUID,
						   	headerData.countOfBinaryBytes.to_bytes(4, 'little'),
							headerData.countOfIntegers.to_bytes(4, 'little'),
							headerData.countOfEightByteValues.to_bytes(4, 'little'),
							headerData.stringAndTypesBufferSize.to_bytes(4, "little"),
						   	preallocValues, uncompressedSize, compressedSize, 
							blockCount.to_bytes(4, "little"), blockTotalSize.to_bytes(4, "little"), 
							unknowns])

	header_info.size = len(blockDataBase + blockDataCompressed)
	if g_isVerbose:
		print(f"Stats for {visualName} block (UUID: {str(UUID(bytes_le=guid))}):")
		print(f"countOfStrings: {headerData.countOfStrings} | len(strings): {len(headerData.strings)}")
		print(f"countOfIntegers: {headerData.countOfIntegers}")
		print(f"countOfDoubles: {headerData.countOfEightByteValues}")
		print(f"countOfBinaryBytes: {headerData.countOfBinaryBytes}")
		print(f"stringsAndTypesBufferSize {headerData.stringAndTypesBufferSize}")
		print(f"typesLength {len(headerData.types)}")
		print(f"uncompressedSize: {len(blockDataUncompressed)}")
		print(f"compressedSize: {len(blockDataCompressed)}")
		print(f"Final block size: {header_info.size}\n")

	return b''.join([blockDataBase, blockDataCompressed])

def debugWriteListToFile(name, list):
	file = open(name, "w")
	for v in list:
		file.write(str(v) + "\n")
	file.close()

# special types like DOUBLE_ZERO, INT64_ONE can't exist in typed arrays, so we use default types
def getKVTypeFromInstance(obj, inTypedArray: bool = False):
	if type(obj) is list:
		if(len(obj) > 0 and len(obj) < 256):
			return KVType.ARRAY_TYPE_BYTE_LENGTH
		elif(len(obj) > 0):
			return KVType.ARRAY_TYPED
		else: # len == 0
			return KVType.ARRAY
	elif type(obj) is dict:
		return KVType.OBJECT
	elif type(obj) is str:
		return KVType.STRING
	elif isinstance(obj, bool):
		if obj == True:
			return KVType.BOOLEAN_TRUE
		else:
			return KVType.BOOLEAN_FALSE
	elif isinstance(obj, int):
		if obj == 0 and inTypedArray == False:
			return KVType.INT64_ZERO
		elif obj == 1 and inTypedArray == False:
			return KVType.INT64_ONE
		else:
			# it seems not all values that are above or equal 0 are marked as unsigned in official assets.
			# however in this case if we know that we can't fit a unsigned value into 32bit signed int, so we use uint32
			# TODO: What about 64 bit values? Haven't found any assets that use them yet.
			if obj <= 2147483647:
				return KVType.INT32
			else:
				return KVType.UINT32
	elif isinstance(obj, float):
		if obj == 0.0 and inTypedArray == False:
			return KVType.DOUBLE_ZERO
		elif obj == 1.0 and inTypedArray == False:
			return KVType.DOUBLE_ONE
		else:
			return KVType.DOUBLE
	elif obj is None:
		return KVType.NULL
	else:
		raise ValueError("KV3: Unhandled type: " + type(obj).__name__)

def buildKVStructure(obj, header, inTypedArray, arraySubType: Optional[KVType] = None) -> bytes:
	#global types, countOfIntegers, countOfEightByteValues, countOfStrings, binaryBytes, countOfBinaryBytes
	data: list[bytes] = []
	currentType = getKVTypeFromInstance(obj, inTypedArray)
	if type(obj) is dict:
		if inTypedArray == False:
			header.types += currentType.to_bytes(1)
		length: int = len(obj)
		data += length.to_bytes(4, "little") # for dicts append length at start!
		header.countOfIntegers += 1
		for key, value in obj.items():
			if type(key) is str: # keys don't get types since they're always strings
				stringID = len(header.strings)
				if key in header.strings:
					stringID = header.strings.index(key)
				else:
					header.strings.append(key)
					header.countOfStrings += 1
				data += stringID.to_bytes(4, "little")
				header.countOfIntegers += 1
			else:
				raise ValueError("KV3: Keys must be strings.")
			data += buildKVStructure(value, header, False)
	elif type(obj) is list:
		# inside typed arrays we only add the type once (already done up in the call stack in this case)
		if inTypedArray == False:
			header.types += currentType.to_bytes(1)
		if(len(obj) > 0 and len(obj) < 256) and arraySubType != KVType.ARRAY: # special case if the internal arrays have been tagged as different type.
			header.binaryBytes += len(obj).to_bytes(1)
			header.countOfBinaryBytes += 1
		else: # length bigger than 1 byte
			data += len(obj).to_bytes(4, "little")
			header.countOfIntegers += 1

		if len(obj) > 0:
			# if there's mixed "optimized" types in the array then we use the least specific one. That's why we iterate.
			# eg. we know that arrays of 0 length get the ARRAY type and ARRAY_TYPE_BYTE_LENGTH type is used for arrays with 1-255 elements.
			# if there's at least one empty array, then we assume every element as ARRAY type.
			# TODO: does this only affect arrays or other types? Knowing this is not strictly necessary to output a valid file though.
			subType = None
			for val in obj:
				subType = getKVTypeFromInstance(val, True)
				if subType == KVType.ARRAY:
					break
			if arraySubType != KVType.ARRAY:
				header.types += subType.to_bytes(1)

		for val in obj:
			# we set the last array type here as arrays that contain the same type only save their type ONCE.
			# this is known to be done for a few types described below. Explicit types like DOUBLE_ZERO or INT64_ONE
			# seem to be only saved in non-typed arrays for each element.
			# if we're not in a typed array we add the types right before and note that we are inside an array, so we don't add the type again.
			
			data += buildKVStructure(val, header, arraySubType != KVType.ARRAY, arraySubType = subType)

	elif type(obj) is str:
		stringID = len(header.strings) # we will be adding 1 if we're adding a string so this will actually point at the last element.
		if obj in header.strings:
			stringID = header.strings.index(obj) # Reuse existing id
		elif len(obj) == 0:
			stringID = -1
		else:
			header.strings.append(obj)
			header.countOfStrings += 1
		data += stringID.to_bytes(4, "little", signed=True)
		if inTypedArray == False:
			header.types += currentType.to_bytes(1)
		header.countOfIntegers += 1
	elif isinstance(obj, bool):
		header.types += currentType.to_bytes(1)
		# no additional data...
	elif isinstance(obj, int):
		# 1s and 0s don't get special types in arrays, trying to use them will confuse the game with array size.
		if (obj == 0 or obj == 1) and inTypedArray == False:
			header.types += currentType.to_bytes(1)
		else:
			if inTypedArray == False:
				header.types += currentType.to_bytes(1)
			data += obj.to_bytes(4, "little", signed=True if obj < 0 else False)
			header.countOfIntegers += 1
	elif isinstance(obj, float):
		if (obj == 0.0 or obj == 1.0) and inTypedArray == False:
			header.types += currentType.to_bytes(1)
		else:
			if inTypedArray == False:
				header.types += currentType.to_bytes(1)
			header.doubles.append(obj)
			header.countOfEightByteValues += 1
	elif obj is None:
		header.types += currentType.to_bytes(1)
	else:
		print("unhandled type detected: " + type(obj).__name__)
	return data

@dataclass
class AssetInfo:
	version: int
	headerVersion: int
	blocks: list[FileBlock] # will not contain data, only type and name.

def readBytesFromFile(file: Path | str, type: str) -> bytes:
	try:
		fileData: bytes = None
		if type == "kv3":
			fileData = kv3.read(file)
		elif type == "text":
			with open(file, "r", encoding="utf-8") as f:
				fileData = bytes(f.read(), 'utf-8')
		else:
			raise ValueError("Unsupported file type: " + type)
		return fileData
	except FileNotFoundError as e:
		raise
# Not the prettiest, we might switch to a library later on.
def validateJsonStructure(loadedData):
	if loadedData is None:
		raise ValueError("empty or invalid.")
	if 'info' not in loadedData:
		raise ValueError("missing 'info' section.")
	if 'version' not in loadedData['info']:
		raise ValueError("missing 'version' in 'info' section.")
	else:
		version = loadedData['info']['version']
		if not isinstance(version, int):
			raise ValueError("'version' value must be an integer")
		if version < 0 or version > 65535:
			raise ValueError("invalid version number.")
	# TODO: DRY
	if 'headerversion' not in loadedData['info']:
		raise ValueError("missing 'headerversion' in 'info' section.")
	else:
		version = loadedData['info']['headerversion']
		if not isinstance(version, int):
			raise ValueError("'headerversion' value must be an integer")
		if version < 0 or version > 65535:
			raise ValueError("invalid headerversion number.")
	
	if 'blocks' not in loadedData:
		raise ValueError("missing 'blocks' section.")
	else:
		blocks = loadedData['blocks']
		if not isinstance(blocks, list):
			raise ValueError("'blocks' must be a list.")
		for idx, block in enumerate(blocks):
			if 'type' not in block:
				raise ValueError("missing 'type' key in block no. " + str(idx+1))
			if not isinstance(block['type'], str):
				raise ValueError("'type' must be a string, in block no. " + str(idx+1))
			if block['type'] not in ["kv3", "text"]:
				raise ValueError("'type' must be either 'kv3' or 'text', in block no. " + str(idx+1))
			if 'name' not in block:
				raise ValueError("missing 'name' key in block no. " + str(idx+1))
			if not isinstance(block['name'], str):
				raise ValueError("'name' must be a string, in block no. " + str(idx+1))
			if len(block['name']) != 4:
				raise ValueError("'name' must be a 4 character string, in block no. " + str(idx+1))
			if 'file' not in block:
				raise ValueError("missing 'file' key in block no. " + str(idx+1))
			if not isinstance(block['file'], str):
				raise ValueError("'file' must be a string, in block no. " + str(idx+1))

def parseJsonStructure(file: str):
	try:
		with open(file, "r") as f:
			data = json.load(f)
			validateJsonStructure(data) # will raise errors if something is wrong.
			version = data['info']['version']
			headerVersion = data['info']['headerversion']
			blocks = []
			currentBlock = 1 # for error messages
			for block in data['blocks']:
				block['type'] = block['type'].lower()
				fileData = None
				# search relative to the JSON file
				fullPath = (Path(file).parents[0] / Path(block['file'])).resolve()
				fileData = readBytesFromFile(fullPath, block['type'])
				blocks.append(FileBlock(data=fileData, type=block['type'], name=block['name'], dataProcessed=False))
				currentBlock += 1
			return AssetInfo(version, headerVersion, blocks)
	except FileNotFoundError as e:
		raise FileNotFoundError(f"Failed to open file defined in JSON block {str(currentBlock)}: {e}")
	except json.JSONDecodeError as e:
		raise json.JSONDecodeError("Failed to parse JSON structure file: "+str(e))
	except kv3.KV3DecodeError as e:
		raise kv3.KV3DecodeError("Failed to parse KV3 file: "+str(e))
	except ValueError as e:
		raise ValueError("JSON structure file " + str(e))

assetPresetInfo = {
	"vpulse": AssetInfo(version=0, headerVersion=12, blocks=[
		FileBlock(type="kv3", name="RED2", data=None, dataProcessed=False),
		FileBlock(type="kv3", name="DATA", data=None, dataProcessed=False)
	]),
	"vrr": AssetInfo(version=9, headerVersion=12, blocks=[
		FileBlock(type="kv3", name="RED2", data=None, dataProcessed=False),
		FileBlock(type="kv3", name="DATA", data=None, dataProcessed=False)
	]),
	"cs2vanmgrph": AssetInfo(version=0, headerVersion=12, blocks=[
		FileBlock(type="kv3", name="RED2", data=None, dataProcessed=False),
		FileBlock(type="kv3", name="DATA", data=None, dataProcessed=False)
	]),
}
# This section should probably be redone and reuse pre-defined JSONs as templates.
def buildAssetFromPreset(preset: str, files: list[str]) -> bytes:
	if preset not in assetPresetInfo:
		raise ValueError("Unsupported preset: " + preset)
	requiredFileCount = len(assetPresetInfo[preset].blocks)
	try:
		if files is None or len(files) != requiredFileCount:
			raise ValueError(f"Preset '{preset}' requires -f flag with {requiredFileCount} files.")
		assetInfoAndData = deepcopy(assetPresetInfo[preset])
		for idx, block in enumerate(assetInfoAndData.blocks):
			fullPath = Path(files[idx]).resolve()
			block.data = readBytesFromFile(fullPath, block.type)
		return buildFileData(assetInfoAndData.version, assetInfoAndData.headerVersion, assetInfoAndData.blocks)
	except kv3.KV3DecodeError as e:
		raise
	except FileNotFoundError as e:
		raise FileNotFoundError(f"One of the specified files doesn't exist: {e}")
	
def editAssetFile(file: Path | str, replacementData: list[FileBlock]) -> AssetInfo:
	try:
		assetInfo = readAssetFile(file, True)
		for idx, block in enumerate(assetInfo.blocks):
			if block.name == replacementData[idx].name:
				block.data = replacementData[idx].data
		return assetInfo
	except FileNotFoundError as e:
		raise FileNotFoundError(f"Failed to open file: {e}")

def getTypeFromMagic(magic: bytes) -> str:
	if magic == 1263940356:
		return "kv3"
	else: # we don't support other types, so assuming here...
		return "text"

def readAssetFile(file: Path | str, includeData: bool = False) -> AssetInfo:
	try:
		assetInfo: AssetInfo = AssetInfo(0, 0, [])
		with open(file, "rb") as f:
			fileSize = struct.unpack("<I", f.read(4))[0]
			assetInfo.headerVersion = struct.unpack("<H", f.read(2))[0]
			assetInfo.version = struct.unpack("<H", f.read(2))[0]
			blockOffset = struct.unpack("<I", f.read(4))[0]
			blockCount = struct.unpack("<I", f.read(4))[0]
			f.seek(8 + blockOffset, os.SEEK_SET)
			for i in range(blockCount):
				blockName = f.read(4).decode('ascii')
				blockOffset = struct.unpack("<I", f.read(4))[0]
				blockSize = struct.unpack("<I", f.read(4))[0]
				currentOffset = f.tell()
				f.seek(blockOffset - 8, os.SEEK_CUR)

				blockType = getTypeFromMagic(struct.unpack("<I", f.read(4))[0])
				f.seek(-4, os.SEEK_CUR)
				blockData = None
				dataProcessed = False
				if includeData:
					dataProcessed = True
					blockData = f.read(blockSize)
				f.seek(currentOffset, os.SEEK_SET)
				assetInfo.blocks.append(FileBlock(data=blockData, type=blockType, name=blockName, dataProcessed=dataProcessed))
		return assetInfo
	except FileNotFoundError as e:
		raise FileNotFoundError(f"Failed to open file: {e}")
	except struct.error as e:
		raise ValueError(f"Failed to deserialize file: {e} it might not be a valid asset.")

g_isVerbose = False
def printDebug(msg):
	if g_isVerbose:
		print(msg)

if __name__ == "__main__":
	example = '''example:

	%(prog)s -s pulse_schema.json -o output.vpulse_c
	%(prog)s -p vrr -f vrr_redi.kv3 vrr_data.kv3 -o output.vrr_c'''
	parser = argparse.ArgumentParser(description="Tool to assemble Source 2 assets manually.", epilog=example,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")
	input_group = parser.add_mutually_exclusive_group(required=True)
	input_group.add_argument("-b", "--base",
								help="Use a compiled file as a base for the stucture of the file to compile",
								type=str, metavar="<compiled asset file>")
	input_group.add_argument("-s", "--schema",
								help="Use a JSON file with the definition of the file structure to compile (see README for an example)",
								type=str, metavar="<json file>")
	input_group.add_argument("-p", "--preset",
								help="Use a preset for the file structure, supported presets: " + ', '.join(list(assetPresetInfo.keys())),
								type=str, metavar="<preset>")
	input_group.add_argument("-e", "--edit", 
								help="Edit an existing asset file, requires -f flag with the same amount of files as the base file.",
								type=str, nargs="+", metavar="<compiled asset file> <BLOCK1> <BLOCK2> ...")
	parser.add_argument("-f", "--files", 
					 help="List of files to use, only to be used with -b or -p, amount of files depends on the structure of the base file/preset that was specified",
					 type=str, nargs="+", metavar="<file1> <file2> ...")
	parser.add_argument("-o", "--output",
					 help="Output file name",
					 type=str, metavar="<output file>", required=True)
	
	args = parser.parse_args()
	if args.verbose:
		g_isVerbose = True
	binaryData = None
	try:
		if args.schema is not None: # we are using a schema JSON file
			structure = parseJsonStructure(args.schema)
			printDebug(f"Using schema file: {args.schema}")
			binaryData = buildFileData(structure.version, structure.headerVersion, structure.blocks)
		elif args.preset is not None:
			if args.preset.lower() not in list(assetPresetInfo.keys()):
				print("Unsupported preset: "+args.preset)
				sys.exit(1)
			printDebug(f"Using preset: {args.preset}")
			binaryData = buildAssetFromPreset(args.preset, args.files)
		elif args.base is not None:
			if(args.base.endswith("_c") == False):
				print("--base argument requires a compiled asset file.")
				sys.exit(1)
			assetInfo = readAssetFile(args.base)
			binaryData = buildFileData(assetInfo.version, assetInfo.headerVersion, assetInfo.blocks)
		elif args.edit is not None:
			if(args.edit[0].endswith("_c") == False):
				print("--edit argument requires a compiled asset file.")
				sys.exit(1)
			assetInfo: AssetInfo = readAssetFile(args.edit[0], True)
			maxBlocks: int = len(args.edit) - 1
			for idx, file in enumerate(args.files):
				currBlock: int = args.edit[idx+1]
				blockIdx: int = -1
				for currIdx, block in enumerate(assetInfo.blocks):
					if block.name == currBlock:
						blockIdx = currIdx
						break
				else:
					raise ValueError(f"Block {currBlock} not found in the input file.")
				fullPath = Path(file).resolve()
				assetInfo.blocks[blockIdx].data = readBytesFromFile(fullPath, assetInfo.blocks[blockIdx].type)
				assetInfo.blocks[blockIdx].dataProcessed = False # we need to reprocess the data.
			binaryData = buildFileData(assetInfo.version, assetInfo.headerVersion, assetInfo.blocks)
		else:
			print("One of the following flags is required to compile an asset: -s, -p, -b, -e Use -h for help.")
			sys.exit(0)
	except (FileNotFoundError, ValueError) as e: # let's not handle json and kv3 errors, it might be useful to get a full call stack.
		print("ERROR: " + str(e) + ". Asset was not processed.")
		sys.exit(1)
	try:
		with open(args.output, "wb") as f:
			printDebug(f"Writing output file: {args.output}")
			f.write(binaryData)
	except Exception as e:
		print("Failed to write output file: " + str(e))
		sys.exit(1)