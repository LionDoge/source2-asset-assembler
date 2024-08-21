import sys
import keyvalues3 as kv3
import struct
import lz4.block
from enum import IntEnum
from dataclasses import dataclass, field
from typing import Optional
from uuid import UUID
import argparse
import json

class KVTypes(IntEnum):
	STRING_MULTI = 0,
	NULL = 1,
	BOOLEAN = 2,
	INT64 = 3,
	UINT64 = 4,
	DOUBLE = 5,
	STRING = 6,
	BINARY_BLOB = 7,
	ARRAY = 8,
	OBJECT = 9, # dict as well?
	ARRAY_TYPED = 10,
	INT32 = 11,
	UINT32 = 12,
	BOOLEAN_TRUE = 13,
	BOOLEAN_FALSE = 14,
	INT64_ZERO = 15,
	INT64_ONE = 16,
	DOUBLE_ZERO = 17,
	DOUBLE_ONE = 18,
	FLOAT = 19,
	UNKNOWN_20 = 20,
	UNKNOWN_21 = 21,
	UNKNOWN_22 = 22,
	INT32_AS_BYTE = 23,
	ARRAY_TYPE_BYTE_LENGTH = 24

@dataclass
class FileHeaderInfo:
	size: int = 0
	offset: int = 0
	additional_bytes: int = 0

@dataclass
class FileBlock:
	data: any
	type: str
	name: str

@dataclass
class KVBaseData:
	strings: list[str] = field(default_factory=list)
	types: list[bytes] = field(default_factory=list)
	binaryBytes: list[bytes] = field(default_factory=list) # this list sits at almost the beginning of kv data.
	countOfIntegers: int = 0
	countOfEightByteValues: int = 0
	stringAndTypesBufferSize: int = 0
	doubles: list[float] = field(default_factory=list)
	countOfStrings: int = 0
	countOfBinaryBytes: int = 0

def writeFileData(version: int, headerVersion: int, blocks: list[FileBlock]):
	fileSize = 0 # 0
	printDebug(f"version: {version}\nheader version: {headerVersion}\nblock count: {len(blocks)}\n")
	headerVersion = headerVersion.to_bytes(2, 'little') # 4
	version = version.to_bytes(2, 'little') # 6

	blockOffset = 8 # TODO is this always the same? # 8
	blockOffset = blockOffset.to_bytes(4, 'little') # 12

	blockCount = len(blocks)
	blockCount = blockCount.to_bytes(4, 'little') # 16

	combinedBlockHeaderData = b''
	fileSize += (16 + 12*len(blocks)) # 16 is the size of the header, 12 is the size of each block header (name, offset, size)
	headerPadAmount = -fileSize % 16
	fileSize += headerPadAmount # the data is also padded with 0s to align to 16 bytes.

	# the offsets are relative to where they are placed in the file, we should know the first one's value, since the first block of data is right after the header.
	# first offset: 8 is the offset to another block info, every block info is 12 bytes long.
	currentOffset = 8 + ((len(blocks) - 1) * 12) + headerPadAmount
	dataBlocks = []
	for idx, block in enumerate(blocks):
		printDebug(f"Processing block {idx+1} (name: {block.name} type: {block.type})")
		if block.type == "kv3":
			blockHeaderInfo = FileHeaderInfo()
			blockUUID: UUID = block.data.format.version
			alignEnd = True
			if idx == len(blocks)-1:
				alignEnd = False
			blockKVData = writeKVBlock(block.data, blockUUID.bytes_le, blockHeaderInfo, alignEnd=alignEnd, visualName=block.name)
			dataBlocks.append(blockKVData)
			fileSize += blockHeaderInfo.size + blockHeaderInfo.additional_bytes

			combinedBlockHeaderData += b''.join([block.name.encode('ascii'), currentOffset.to_bytes(4, 'little'), blockHeaderInfo.size.to_bytes(4, 'little')])
			currentOffset += blockHeaderInfo.size + blockHeaderInfo.additional_bytes
		elif block.type == "text":
			dataBlocks.append(block.data)
			fileSize += len(block.data)
			currentOffset += len(block.data)
			printDebug(f"Stats for {block.name} block (UUID: {str(UUID(bytes_le=blockUUID))}):")
			printDebug(f"Text size: {len(block.data)}\n")
		currentOffset -= 12 # -12 because we need to account for where the next offset value is placed.
	
	binData = b''.join([fileSize.to_bytes(4, 'little'), headerVersion, version, blockOffset, blockCount, # FILE HEADER (16 bytes)
				   combinedBlockHeaderData, (b'\x00'*headerPadAmount)]) # HEADER DATA FOR BLOCKS + PADDING
	for block in dataBlocks:
		binData += block # DATA BLOCKS
	printDebug(f"Final file size: {fileSize} bytes")
	return binData

KV3_FORMAT_GUID = b'\x7C\x16\x12\x74\xE9\x06\x98\x46\xAF\xF2\xE6\x3E\xB5\x90\x37\xE7'
def writeKVBlock(block_data, guid, header_info, alignEnd=False, visualName: str = "unnamed block"):
	headerData = KVBaseData()
	kv3ver = b'\x04' # For now we only support version 4 of KV3
	encodedGUID = guid
	constantsAfterGUID = b'\x01\x00\x00\x00\x00\x00\x00\x40' # contains compressionMethod, compressionDictionaryID and compressionFrameSize.
	# The redefinitions here are written merely for the sake of readability.
	headerData.countOfBinaryBytes = 0
	headerData.countOfIntegers = 1 # All of the actual kv Data plus countOfStrings, which is always here, so we start from one.
	headerData.countOfEightByteValues = 0
	headerData.stringAndTypesBufferSize = 0 #! length of strings + length of types combined
	#! Apparently these are used to preallocate something, for safety I'll put in FFFF, it seems to be working fine so far.
	preallocValues = b'\xFF\xFF\xFF\xFF'

	headerData.uncompressedSize = 0 # decompressed kv3 block size
	headerData.compressedSize = 0 # compressed kv3 block size
	blockCount = 0 # always the same
	blockTotalSize = 0 # always the same
	unknowns = b'\x00'*8 # Appears to always be the same - can ignore.
	# after all this we finally have actual kv data...

	# ------ DATA LATER IS LZ4 COMPRESSED! -------
	# ! We have to fill it with 0s afterwards so it aligns to 4 bytes!
	headerData.binaryBytes = [] # length is count of binary bytes

	headerData.countOfStrings = 0
	# after countOfStrings we have data about the structure, mostly because the data is actually just integers that references stuff.
	kvData = b''
	headerData.doubles = []
	doublesBytes = b"" # transformed for appending
	# after list of doubles we have a list of null terminated strings:
	headerData.strings = [] # ! add strings here as we go parsing the kv text data.
	stringsBytes = [] # transformed for appending

	# after strings there is list of types, each one is one byte, the length is amount of types that we get from substracting string length from 'stringAndTypesLength'
	headerData.types = []
	# this comes after types list.
	noBlocksTrailer = 4293844224 # this should always be this value.
	kvData = writeKVStructure(block_data.value, headerData, False)
	headerData.countOfStrings = len(headerData.strings)
	headerData.countOfBinaryBytes = len(headerData.binaryBytes)
	# terminate all strings
	for s in headerData.strings:
		stringsBytes.append(bytes(s, "ascii")+b'\x00')

	headerData.stringAndTypesBufferSize = len(headerData.types) + len(b''.join(stringsBytes))
	headerData.binaryBytes = bytes(headerData.binaryBytes)
	headerData.binaryBytes += b'\x00'* (-len(headerData.binaryBytes) % 4) # align to 4 bytes

	for v in headerData.doubles:
		doublesBytes += struct.pack("<d", v) # little-endian eight bytes

	infoSectionLen = len(kvData) + 4 + len(headerData.binaryBytes)
	kvData += b'\x00'*(-infoSectionLen % 8) # make sure that ints align to 8 bytes, as we have doubles next!

	blockDataUncompressed = b''.join([headerData.binaryBytes, headerData.countOfStrings.to_bytes(4, "little"),
								  	bytes(kvData), doublesBytes, b''.join(stringsBytes), bytes(headerData.types),
									noBlocksTrailer.to_bytes(4, "little")])
	
	# values tested based on 2v2_enable.vpulse_c
	blockDataCompressed = lz4.block.compress(blockDataUncompressed, mode='high_compression',compression=11,store_size=False) 
	uncompressedSize = len(blockDataUncompressed).to_bytes(4, "little")
	compressedSize = len(blockDataCompressed).to_bytes(4, "little")

	blockDataBase = b''.join([kv3ver, "3VK".encode('ascii'), encodedGUID, constantsAfterGUID,
						   	headerData.countOfBinaryBytes.to_bytes(4, 'little'),
							headerData.countOfIntegers.to_bytes(4, 'little'),
							headerData.countOfEightByteValues.to_bytes(4, 'little'),
							headerData.stringAndTypesBufferSize.to_bytes(4, "little"),
						   	preallocValues, uncompressedSize, compressedSize, 
							blockCount.to_bytes(4, "little"), blockTotalSize.to_bytes(4, "little"), 
							unknowns])

	header_info.size = len(blockDataBase + blockDataCompressed)
	if alignEnd == True:
		# ! Assumption from what I observed: All blocks after another start aligned to 16 bytes, 
		# ! so if we don't have enough bytes for a full line at the end in hex editor then append 0s and only then start the next block. 
		bytesToAdd = 16 - (len(blockDataCompressed + blockDataBase) % 16)
		blockDataCompressed += b'\x00'*bytesToAdd
		header_info.additional_bytes += bytesToAdd

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
		file.write(str(v)+"\n")
	file.close()

# special types like DOUBLE_ZERO, INT64_ONE can't exist in arrays, so we use default types
def getKVTypeFromInstance(obj, inArray: bool = False):
	if type(obj) is list:
		if(len(obj) > 0 and len(obj) < 256):
			return KVTypes.ARRAY_TYPE_BYTE_LENGTH
		elif(len(obj) > 0):
			return KVTypes.ARRAY_TYPED
		else: # len == 0
			return KVTypes.ARRAY
	elif type(obj) is dict:
		return KVTypes.OBJECT
	elif type(obj) is str:
		return KVTypes.STRING
	elif isinstance(obj, bool):
		if obj == True:
			return KVTypes.BOOLEAN_TRUE
		else:
			return KVTypes.BOOLEAN_FALSE
	elif isinstance(obj, int):
		if obj == 0 and inArray == False:
			return KVTypes.INT64_ZERO
		elif obj == 1 and inArray == False:
			return KVTypes.INT64_ONE
		else:
			# it seems not all values that are above or equal 0 are marked as unsigned in official assets.
			# however in this case if we know that we can't fit a unsigned value into 32bit signed int, so we use uint32
			# TODO: What about 64 bit values? Haven't found any assets that use them yet.
			if obj <= 2147483647:
				return KVTypes.INT32
			else:
				return KVTypes.UINT32
	elif isinstance(obj, float):
		if obj == 0.0 and inArray == False:
			return KVTypes.DOUBLE_ZERO
		elif obj == 1.0 and inArray == False:
			return KVTypes.DOUBLE_ONE
		else:
			return KVTypes.DOUBLE
	elif obj is None:
		return KVTypes.NULL

def writeKVStructure(obj, header, inTypedArray, arraySubType: Optional[KVTypes] = None):
	#global types, countOfIntegers, countOfEightByteValues, countOfStrings, binaryBytes, countOfBinaryBytes
	data: list[bytes] = []
	currentType = getKVTypeFromInstance(obj, inTypedArray)
	if type(obj) is dict:
		if inTypedArray == False:
			header.types += currentType.to_bytes(1)
		length: int = len(obj)
		data += length.to_bytes(4, "little") # for dicts append length at start!
		header.countOfIntegers+=1
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
				raise ValueError("KV3 Keys must be strings.")
			data += writeKVStructure(value, header, False)
	elif type(obj) is list:
		# looks like if we have inside one array they get treated as one, thus we don't add another type to the list. We will use this value to detect that.
		if inTypedArray == False:
			header.types += currentType.to_bytes(1)
		if(len(obj) > 0 and len(obj) < 256) and arraySubType != KVTypes.ARRAY: # special case if the internal arrays have been tagged as different type.
			header.binaryBytes += len(obj).to_bytes(1)
			header.countOfBinaryBytes += 1
		else: # length bigger than 1 byte
			data += len(obj).to_bytes(4, "little")
			header.countOfIntegers += 1

		# arrays have types, if we get the first element's type, then we know the type of the array.
		if len(obj) > 0:
			# if there's mixed "optimized" types in the array then we use the least specific one.
			# eg. we know that arrays of 0 length get the ARRAY type and ARRAY_TYPE_BYTE_LENGTH type is used for arrays with 1-255 elements.
			# if there's at least one empty array, then we assume every element as ARRAY type.
			# TODO, it appears that types such as INT64_ONE and similar sometimes also get saved in the array, but not always. When is that the case?
			subType = None
			for val in obj:
				subType = getKVTypeFromInstance(val, True)
				if subType == KVTypes.ARRAY:
					break
			if arraySubType != KVTypes.ARRAY:
				header.types += subType.to_bytes(1)

		for val in obj:
			# we set the last array type here as arrays that contain the same type only save their type ONCE.
			# this is known to be done for a few types described below. Explicit types like DOUBLE_ZERO or INT64_ONE seem to be always repeated.
			# we add the types here, and note that we are inside an array, so we don't add the type again.
			
			data += writeKVStructure(val, header, arraySubType != KVTypes.ARRAY, arraySubType = subType)

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
		print("unhandled type detected: "+type(obj).__name__)
	return data

@dataclass
class JsonStructureInfo:
	version: int
	headerVersion: int
	blocks: list[FileBlock]

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

# TODO: Maybe also return the file types that are required for the preset?
def getRequiredFilesForPreset(preset: str):
	if preset == "vpulse":
		return 2
	elif preset == "vrr":
		return 2
	elif preset == "cs2vanmgrph":
		return 2
	else:
		raise ValueError("Unsupported preset: "+preset)
	
SUPPORTED_PRESETS = ["vpulse", "vrr", "cs2vanmgrph"]
def writeFileFromPreset(preset: str, files: list[str]):
	if preset not in SUPPORTED_PRESETS:
		raise ValueError("Unsupported preset: "+preset)
	requiredFileCount = getRequiredFilesForPreset(preset)
	# TODO: Move preset definitions to json files.
	try:
		if preset == "vpulse":
			if files is None or len(files) != requiredFileCount:
				raise ValueError(f"Preset '{preset}' requires -f flag with {requiredFileCount} files.")
			return writeFileData(0, 12, [
				FileBlock(data=kv3.read(args.files[0]), type="kv3", name="RED2"),
				FileBlock(data=kv3.read(args.files[1]), type="kv3", name="DATA")
			])
		elif preset == "vrr":
			if files is None or len(files) != requiredFileCount:
				raise ValueError(f"Preset '{preset}' requires -f flag with {requiredFileCount} files.")
			return writeFileData(9, 12, [
				FileBlock(data=kv3.read(args.files[0]), type="kv3", name="RED2"),
				FileBlock(data=kv3.read(args.files[1]), type="kv3", name="DATA")
			])
		elif preset == "cs2vanmgrph":
			if files is None or len(files) != requiredFileCount:
				raise ValueError(f"Preset '{preset}' requires -f flag with {requiredFileCount} files.")
			return writeFileData(0, 12, [
				FileBlock(data=kv3.read(args.files[0]), type="kv3", name="RED2"),
				FileBlock(data=kv3.read(args.files[1]), type="kv3", name="DATA")
			])
	except kv3.KV3DecodeError as e:
		raise
	except FileNotFoundError as e:
		raise FileNotFoundError(f"One of the specified files doesn't exist: {e}")

g_isVerbose = False
def printDebug(msg):
	if g_isVerbose:
		print(msg)

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
				block['name'] = block['name'].upper()
				block['type'] = block['type'].lower()
				fileData = None
				if block['type'] == "kv3":
					fileData = kv3.read(block['file'])
				elif block['type'] == "text":
					with open(block['file'], "r") as f:
						fileData = bytes(f.read(), 'ascii')
				blocks.append(FileBlock(data=fileData, type=block['type'], name=block['name']))
				currentBlock += 1
			return JsonStructureInfo(version, headerVersion, blocks)
	except FileNotFoundError as e:
		raise FileNotFoundError(f"Failed to open file defined in JSON block {str(currentBlock)}: {e}")
	except json.JSONDecodeError as e:
		raise json.JSONDecodeError("Failed to parse JSON structure file: "+str(e))
	except kv3.KV3DecodeError as e:
		raise kv3.KV3DecodeError("Failed to parse KV3 file: "+str(e))
	except ValueError as e:
		raise ValueError("JSON structure file " + str(e))

if __name__ == "__main__":
	example = '''example:

	%(prog)s -s pulse_schema.json -o output.vpulse_c
	%(prog)s -p vrr -f vrr_redi.kv3 vrr_data.kv3 -o output.vrr_c'''
	parser = argparse.ArgumentParser(description="Tool to assemble Source 2 assets manually.", epilog=example,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")
	file_struct_group = parser.add_mutually_exclusive_group(required=True)
	file_struct_group.add_argument("-b", "--base",
								help="Use a compiled file as a base for the stucture of the file to compile",
								type=str, metavar="<compiled asset file>")
	file_struct_group.add_argument("-s", "--schema",
								help="Use a JSON file with the definition of the file structure to compile (see README for an example)",
								type=str, metavar="<json file>")
	file_struct_group.add_argument("-p", "--preset",
								help="Use a preset for the file structure, supported presets: " + ', '.join(SUPPORTED_PRESETS),
								type=str, metavar="<preset>")
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
			binaryData = writeFileData(structure.version, structure.headerVersion, structure.blocks)
		elif args.preset is not None:
			if args.preset.lower() not in SUPPORTED_PRESETS:
				print("Unsupported preset: "+args.preset)
				sys.exit(1)
			printDebug(f"Using preset: {args.preset}")
			binaryData = writeFileFromPreset(args.preset, args.files)
		elif args.base is not None:
			raise NotImplementedError("Not implemented yet.")
	except (FileNotFoundError, ValueError) as e: # let's not handle json and kv3 errors, it might be useful to get a full call stack.
		print(str(e))
		sys.exit(1)
	try:
		with open(args.output, "wb") as f:
			printDebug(f"Writing output file: {args.output}")
			f.write(binaryData)
	except Exception as e:
		print("Failed to write output file: "+str(e))
		sys.exit(1)