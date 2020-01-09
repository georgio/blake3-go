package blake3

import (
	"encoding/binary"
	"math/bits"
)

const (
	OutputLength uint = 32
	KeyLength    uint = 32
	BlockLength  uint = 64
	ChunkLength  uint = 1024

	ChunkStart        uint32 = 1 << 0
	ChunkEnd          uint32 = 1 << 1
	Parent            uint32 = 1 << 2
	Root              uint32 = 1 << 3
	KeyedHash         uint32 = 1 << 4
	DeriveKeyContext  uint32 = 1 << 5
	DeriveKeyMaterial uint32 = 1 << 6
)

var iv = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}
var MessagePermutation = [16]uint{
	2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8,
}

// spec page 5
func g(state *[16]uint32, a uint, b uint, c uint, d uint, mx uint32, my uint32) {
	state[a] += state[b] + mx

	state[d] = bits.RotateLeft32((state[d] ^ state[a]), -16)

	state[c] += state[d]

	state[b] = bits.RotateLeft32((state[b] ^ state[c]), -12)

	state[a] += state[b] + my

	state[d] = bits.RotateLeft32((state[d] ^ state[a]), -8)

	state[c] += state[d]

	state[b] = bits.RotateLeft32((state[b] ^ state[c]), -7)
}

func round(state *[16]uint32, message *[16]uint32) {
	// mix columns
	g(state, 0, 4, 8, 12, message[0], message[1])
	g(state, 1, 5, 9, 13, message[2], message[3])
	g(state, 2, 6, 10, 14, message[4], message[5])
	g(state, 3, 7, 11, 15, message[6], message[7])
	// mix diags
	g(state, 0, 5, 10, 15, message[8], message[9])
	g(state, 1, 6, 11, 12, message[10], message[11])
	g(state, 2, 7, 8, 13, message[12], message[13])
	g(state, 3, 4, 9, 14, message[14], message[15])
}

func permute(message *[16]uint32) {
	var temp = [16]uint32{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	for i := 0; i < 16; i++ {
		temp[i] = message[MessagePermutation[i]]
	}
	*message = temp
}

func compress(chainingValue *[8]uint32, blockWords *[16]uint32, counter uint64, blockLength uint32, flags uint32) [16]uint32 {
	var state = [16]uint32{
		chainingValue[0], chainingValue[1], chainingValue[2], chainingValue[3], chainingValue[4], chainingValue[5], chainingValue[6], chainingValue[7],
		iv[0], iv[1], iv[2], iv[3],
		uint32(counter),
		uint32(counter >> 32),
		blockLength,
		flags,
	}
	// 7 rounds
	round(&state, blockWords)
	permute(blockWords)

	round(&state, blockWords)
	permute(blockWords)

	round(&state, blockWords)
	permute(blockWords)

	round(&state, blockWords)
	permute(blockWords)

	round(&state, blockWords)
	permute(blockWords)

	round(&state, blockWords)
	permute(blockWords)

	round(&state, blockWords)
	permute(blockWords)

	for i := 0; i < 8; i++ {
		state[i] ^= state[i+8]
		state[i+8] ^= chainingValue[i]
	}
	return state
}

func firstEightWords(compressionOutput [16]uint32) (output [8]uint32) {
	copy(output[:], compressionOutput[:8])
	return
}

func wordsFromLitteEndianBytes(bytes []byte, words []uint32) {
	for i := 0; i < len(bytes); i += 4 {
		words[i/4] = binary.LittleEndian.Uint32(bytes[i:])
	}
}

type Output struct {
	inputChainingValue [8]uint32
	blockWords         [16]uint32
	counter            uint64
	blockLength        uint32
	flags              uint32
}

func (output *Output) chainingValue() [8]uint32 {
	return firstEightWords(compress(
		&output.inputChainingValue,
		&output.blockWords,
		output.counter,
		output.blockLength,
		output.flags,
	))
}

//incomplete
func (output *Output) rootOutputBytes(outputSlice []uint8) {
	var outputBlockCounter uint64 = 0
	// figure out condition here
	for true {
		var words = compress(
			&output.inputChainingValue,
			&output.blockWords,
			outputBlockCounter,
			output.blockLength,
			output.flags|Root,
		)
		var outWord []uint8
		var word uint32
		var wordBytes []uint8
		// figure out condition here
		for true {
			// missing assignments
			binary.LittleEndian.PutUint32(wordBytes, word)
			copy(outWord, wordBytes)
		}
		outputBlockCounter++
	}
}

type ChunkState struct {
	chainingValue    [8]uint32
	chunkCounter     uint64
	block            [BlockLength]uint8
	blockLength      uint8
	blocksCompressed uint8
	flags            uint32
}

func newChunkState(key [8]uint32, chunkCounter uint64, flags uint32) ChunkState {
	return ChunkState{
		chainingValue:    key,
		chunkCounter:     chunkCounter,
		block:            [BlockLength]uint8{0, 0, 0, 0, 0, 0, 0, 0},
		blockLength:      0,
		blocksCompressed: 0,
		flags:            flags,
	}
}

func (chunkstate *ChunkState) len() uint {
	return BlockLength*uint(chunkstate.blocksCompressed) + uint(chunkstate.blockLength)
}

func (chunkstate *ChunkState) startFlag() uint32 {
	if chunkstate.blocksCompressed == 0 {
		return ChunkStart
	}
	return 0
}

func (chunkstate *ChunkState) update(input []uint8) {
	for len(input) != 0 {
		if uint(chunkstate.blockLength) == BlockLength {
			var blockWords = [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
			wordsFromLitteEndianBytes(chunkstate.block[:], blockWords[:])
			chunkstate.chainingValue = firstEightWords(compress(&chunkstate.chainingValue, &blockWords, chunkstate.chunkCounter, uint32(BlockLength), chunkstate.flags|chunkstate.startFlag()))
			chunkstate.blocksCompressed++
			chunkstate.block = [BlockLength]uint8{
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			}
			chunkstate.blockLength = 0
		}
		var want uint = BlockLength - uint(chunkstate.blockLength)
		var take uint

		if want >= uint(len(input)) {
			take = want
		} else {
			take = uint(len(input))
		}
		copy(chunkstate.block[uint(chunkstate.blockLength):take], input[:take])
		chunkstate.blockLength += uint8(take)
		input = input[take:]
	}
}

func (chunkstate *ChunkState) output() *Output {
	var blockWords = [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	wordsFromLitteEndianBytes(chunkstate.block[:], blockWords[:])
	return &Output{
		inputChainingValue: chunkstate.chainingValue,
		blockWords:         blockWords,
		blockLength:        uint32(chunkstate.blockLength),
		counter:            chunkstate.chunkCounter,
		flags:              chunkstate.flags | chunkstate.startFlag() | ChunkEnd,
	}
}

func parentOutput(leftChildCV [8]uint32, rightChildCV [8]uint32, key [8]uint32, flags uint32) *Output {
	var blockWords = [16]uint32{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	copy(blockWords[:8], leftChildCV[:])
	copy(blockWords[8:], rightChildCV[:])
	return &Output{
		inputChainingValue: key,
		blockWords:         blockWords,
		blockLength:        uint32(BlockLength),
		counter:            0,
		flags:              Parent | flags,
	}
}

func parentCV(leftChildCV [8]uint32, rightChildCV [8]uint32, key [8]uint32, flags uint32) [8]uint32 {
	return parentOutput(leftChildCV, rightChildCV, key, flags).chainingValue()
}

type Hasher struct {
	chunkState    ChunkState
	key           [8]uint32
	cvStack       [54][8]uint32
	cvStackLength uint
	flags         uint32
}

func newInternalHasher(key [8]uint32, flags uint32) *Hasher {
	return &Hasher{
		chunkState:    newChunkState(key, 0, flags),
		key:           key,
		cvStackLength: 0,
		flags:         flags,
	}
}

func newHasher() *Hasher {
	return newInternalHasher(iv, 0)
}

func newKeyedHasher(key [KeyLength]uint8) *Hasher {
	var keyWords = [8]uint32{0, 0, 0, 0, 0, 0, 0, 0}
	wordsFromLitteEndianBytes(key[:], keyWords[:])
	return newInternalHasher(keyWords, KeyedHash)
}

func newDeriveKey(context string) *Hasher {
	var contextHasher = newInternalHasher(iv, DeriveKeyContext)
	contextHasher.update([]byte(context))
	var contextKey = [KeyLength]uint8{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	contextHasher.finalize(contextKey[:])
	var contextKeyWords = [8]uint32{
		0, 0, 0, 0, 0, 0, 0, 0,
	}
	wordsFromLitteEndianBytes(contextKey[:], contextKeyWords[:])
	return newInternalHasher(contextKeyWords, DeriveKeyMaterial)
}

func (hasher *Hasher) pushStack(cv [8]uint32) {
	hasher.cvStack[uint(hasher.cvStackLength)] = cv
	hasher.cvStackLength++
}

func (hasher *Hasher) popStack() [8]uint32 {
	// check 0 length ?
	hasher.cvStackLength--
	return hasher.cvStack[uint(hasher.cvStackLength)]
}

func (hasher *Hasher) addChunkChainingValue(newCV [8]uint32, totalChunks uint64) {
	for totalChunks&1 == 0 {
		newCV = parentCV(hasher.popStack(), newCV, hasher.key, hasher.flags)
		totalChunks >>= 1
	}
	hasher.pushStack(newCV)
}

func (hasher *Hasher) update(input []uint8) {
	for len(input) != 0 {
		if hasher.chunkState.len() == ChunkLength {
			var chunkCV = hasher.chunkState.output().chainingValue()
			var totalChunks = hasher.chunkState.chunkCounter + 1
			hasher.addChunkChainingValue(chunkCV, totalChunks)
			hasher.chunkState = newChunkState(hasher.key, totalChunks, hasher.flags)
		}
		var want = ChunkLength - hasher.chunkState.len()
		var take uint

		if want >= uint(len(input)) {
			take = want
		} else {
			take = uint(len(input))
		}
		hasher.chunkState.update(input[:take])
		input = input[take:]
	}
}

func (hasher *Hasher) finalize(outputSlice []uint8) {
	var output = hasher.chunkState.output()
	var parentNodesRemaining = uint(hasher.cvStackLength)
	for parentNodesRemaining > 0 {
		output = parentOutput(
			hasher.cvStack[parentNodesRemaining],
			output.chainingValue(),
			hasher.key,
			hasher.flags,
		)
	}
	output.rootOutputBytes(outputSlice)
}
