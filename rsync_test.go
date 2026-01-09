package rsync

import (
	"bytes"
	"context"
	"crypto/md5"
	"strings"
	"testing"
	"time"
)

// TestCreateSignature tests basic signature creation
func TestCreateSignature(t *testing.T) {
	rs := &RSync{
		BlockSize: 4,
	}

	target := strings.NewReader("Hello World!")
	var signatures []BlockHash

	err := rs.CreateSignature(target, func(bl BlockHash) error {
		signatures = append(signatures, bl)
		return nil
	})

	if err != nil {
		t.Fatalf("CreateSignature failed: %v", err)
	}

	// "Hello World!" with block size 4 should create 3 blocks
	// Block 0: "Hell" (4 bytes)
	// Block 1: "o Wo" (4 bytes)
	// Block 2: "rld!" (4 bytes)
	expectedBlocks := 3
	if len(signatures) != expectedBlocks {
		t.Errorf("Expected %d blocks, got %d", expectedBlocks, len(signatures))
	}

	// Verify each signature has required fields
	for i, sig := range signatures {
		if sig.Index != uint64(i) {
			t.Errorf("Block %d has wrong index: %d", i, sig.Index)
		}
		if sig.WeakHash == 0 {
			t.Errorf("Block %d has zero weak hash", i)
		}
		if len(sig.StrongHash) == 0 {
			t.Errorf("Block %d has empty strong hash", i)
		}
	}
}

// TestCreateSignatureWithContext tests context cancellation
func TestCreateSignatureWithContext(t *testing.T) {
	rs := &RSync{
		BlockSize: 4,
	}

	// Create a context that's already cancelled
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	target := strings.NewReader("Hello World!")
	err := rs.CreateSignatureWithContext(ctx, target, func(bl BlockHash) error {
		return nil
	})

	if err != context.Canceled {
		t.Errorf("Expected context.Canceled error, got: %v", err)
	}
}

// TestCreateSignatureWithTimeout tests context timeout
func TestCreateSignatureWithTimeout(t *testing.T) {
	rs := &RSync{
		BlockSize: 4,
	}

	// Create a context with very short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	time.Sleep(10 * time.Millisecond) // Ensure timeout occurs

	target := strings.NewReader(strings.Repeat("A", 10000))
	err := rs.CreateSignatureWithContext(ctx, target, func(bl BlockHash) error {
		return nil
	})

	if err != context.DeadlineExceeded {
		t.Errorf("Expected context.DeadlineExceeded error, got: %v", err)
	}
}

// TestBlockHashCount tests block count calculation
func TestBlockHashCount(t *testing.T) {
	tests := []struct {
		name         string
		blockSize    int
		targetLength int
		expected     int
	}{
		{"Exact fit", 10, 100, 10},
		{"With remainder", 10, 105, 11},
		{"Single block", 100, 50, 1},
		{"Empty", 10, 0, 0},
		{"Default block size", 0, DefaultBlockSize * 3, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rs := &RSync{BlockSize: tt.blockSize}
			count := rs.BlockHashCount(tt.targetLength)
			if count != tt.expected {
				t.Errorf("Expected %d blocks, got %d", tt.expected, count)
			}
		})
	}
}

// TestApplyDelta tests applying delta operations
func TestApplyDelta(t *testing.T) {
	rs := &RSync{
		BlockSize: 4,
	}

	// Target: "Hello World!"
	targetSeeker := strings.NewReader("Hello World!")

	// Create operations to reconstruct "Hello World!"
	ops := make(chan Operation, 10)
	go func() {
		defer close(ops)
		ops <- Operation{Type: OpBlock, BlockIndex: 0} // "Hell"
		ops <- Operation{Type: OpBlock, BlockIndex: 1} // "o Wo"
		ops <- Operation{Type: OpBlock, BlockIndex: 2} // "rld!"
	}()

	var output bytes.Buffer
	err := rs.ApplyDelta(&output, targetSeeker, ops)
	if err != nil {
		t.Fatalf("ApplyDelta failed: %v", err)
	}

	result := output.String()
	expected := "Hello World!"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

// TestApplyDeltaWithNewData tests applying delta with new data
func TestApplyDeltaWithNewData(t *testing.T) {
	rs := &RSync{
		BlockSize: 5,
	}

	targetSeeker := strings.NewReader("Hello")

	// Reconstruct "Hello World!"
	ops := make(chan Operation, 10)
	go func() {
		defer close(ops)
		ops <- Operation{Type: OpBlock, BlockIndex: 0}          // "Hello"
		ops <- Operation{Type: OpData, Data: []byte(" World!")} // New data
	}()

	var output bytes.Buffer
	err := rs.ApplyDelta(&output, targetSeeker, ops)
	if err != nil {
		t.Fatalf("ApplyDelta failed: %v", err)
	}

	result := output.String()
	expected := "Hello World!"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

// TestApplyDeltaBlockRange tests OpBlockRange operation
func TestApplyDeltaBlockRange(t *testing.T) {
	rs := &RSync{
		BlockSize: 2,
	}

	targetSeeker := strings.NewReader("ABCDEFGH")

	// Use block range to copy multiple blocks
	ops := make(chan Operation, 10)
	go func() {
		defer close(ops)
		ops <- Operation{Type: OpBlockRange, BlockIndex: 0, BlockIndexEnd: 3} // "ABCDEFGH"
	}()

	var output bytes.Buffer
	err := rs.ApplyDelta(&output, targetSeeker, ops)
	if err != nil {
		t.Fatalf("ApplyDelta failed: %v", err)
	}

	result := output.String()
	expected := "ABCDEFGH"
	if result != expected {
		t.Errorf("Expected %q, got %q", expected, result)
	}
}

// TestCreateDelta tests delta creation
func TestCreateDelta(t *testing.T) {
	rs := &RSync{
		BlockSize: 5,
	}

	// Target: "Hello"
	target := strings.NewReader("Hello")
	var signatures []BlockHash
	rs.CreateSignature(target, func(bl BlockHash) error {
		signatures = append(signatures, bl)
		return nil
	})

	// Source: "Hello World"
	source := strings.NewReader("Hello World")
	var operations []Operation

	err := rs.CreateDelta(source, signatures, func(op Operation) error {
		// Copy data to avoid buffer reuse issues
		if op.Type == OpData {
			dataCopy := make([]byte, len(op.Data))
			copy(dataCopy, op.Data)
			op.Data = dataCopy
		}
		operations = append(operations, op)
		return nil
	})

	if err != nil {
		t.Fatalf("CreateDelta failed: %v", err)
	}

	// Should have at least one operation
	if len(operations) == 0 {
		t.Error("Expected operations, got none")
	}

	// First operation should reference existing block
	if operations[0].Type != OpBlock && operations[0].Type != OpBlockRange {
		t.Errorf("Expected first operation to be OpBlock or OpBlockRange, got %v", operations[0].Type)
	}
}

// TestEndToEndSync tests complete synchronization workflow
func TestEndToEndSync(t *testing.T) {
	rs := &RSync{
		BlockSize: 4,
	}

	// Original target file
	targetContent := "The quick brown fox jumps over the lazy dog"
	target := strings.NewReader(targetContent)

	// Step 1: Create signature of target
	var signatures []BlockHash
	err := rs.CreateSignature(target, func(bl BlockHash) error {
		signatures = append(signatures, bl)
		return nil
	})
	if err != nil {
		t.Fatalf("CreateSignature failed: %v", err)
	}

	// Modified source file (changed "lazy" to "sleepy")
	sourceContent := "The quick brown fox jumps over the sleepy dog"
	source := strings.NewReader(sourceContent)

	// Step 2: Create delta
	var operations []Operation
	err = rs.CreateDelta(source, signatures, func(op Operation) error {
		if op.Type == OpData {
			dataCopy := make([]byte, len(op.Data))
			copy(dataCopy, op.Data)
			op.Data = dataCopy
		}
		operations = append(operations, op)
		return nil
	})
	if err != nil {
		t.Fatalf("CreateDelta failed: %v", err)
	}

	// Step 3: Apply delta
	ops := make(chan Operation, len(operations))
	for _, op := range operations {
		ops <- op
	}
	close(ops)

	targetSeeker := strings.NewReader(targetContent)
	var output bytes.Buffer
	err = rs.ApplyDelta(&output, targetSeeker, ops)
	if err != nil {
		t.Fatalf("ApplyDelta failed: %v", err)
	}

	// Verify result matches source
	result := output.String()
	if result != sourceContent {
		t.Errorf("Sync failed.\nExpected: %q\nGot:      %q", sourceContent, result)
	}
}

// TestBetaHash tests the rolling hash function
func TestBetaHash(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"Simple", []byte("test")},
		{"Empty", []byte("")},
		{"Single byte", []byte("A")},
		{"Repeated", []byte("AAAA")},
		{"Long", []byte("The quick brown fox")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			β, β1, β2 := βhash(tt.input)

			// Verify β is composed of β1 and β2
			expected := β1 + _M*β2
			if β != expected {
				t.Errorf("β mismatch: got %d, expected %d", β, expected)
			}

			// Verify β1 and β2 are within bounds
			if β1 >= _M {
				t.Errorf("β1 out of bounds: %d >= %d", β1, _M)
			}
			if β2 >= _M {
				t.Errorf("β2 out of bounds: %d >= %d", β2, _M)
			}
		})
	}
}

// TestFindUniqueHash tests hash lookup
func TestFindUniqueHash(t *testing.T) {
	hash1 := md5.Sum([]byte("block1"))
	hash2 := md5.Sum([]byte("block2"))
	hash3 := md5.Sum([]byte("block3"))

	hashes := []BlockHash{
		{Index: 0, StrongHash: hash1[:]},
		{Index: 1, StrongHash: hash2[:]},
		{Index: 2, StrongHash: hash3[:]},
	}

	// Test finding existing hash
	index, found := findUniqueHash(hashes, hash2[:])
	if !found {
		t.Error("Expected to find hash2")
	}
	if index != 1 {
		t.Errorf("Expected index 1, got %d", index)
	}

	// Test not finding hash
	hashNotExist := md5.Sum([]byte("not exist"))
	_, found = findUniqueHash(hashes, hashNotExist[:])
	if found {
		t.Error("Should not find non-existent hash")
	}

	// Test empty hash
	_, found = findUniqueHash(hashes, []byte{})
	if found {
		t.Error("Should not find empty hash")
	}
}

// TestCustomHasher tests using a custom hash function
func TestCustomHasher(t *testing.T) {
	rs := &RSync{
		BlockSize:    4,
		UniqueHasher: md5.New(), // Explicitly set MD5
	}

	target := strings.NewReader("Test")
	var signatures []BlockHash

	err := rs.CreateSignature(target, func(bl BlockHash) error {
		signatures = append(signatures, bl)
		return nil
	})

	if err != nil {
		t.Fatalf("CreateSignature failed: %v", err)
	}

	// MD5 produces 16-byte hashes
	if len(signatures[0].StrongHash) != 16 {
		t.Errorf("Expected 16-byte MD5 hash, got %d bytes", len(signatures[0].StrongHash))
	}
}

// TestLargeFile tests with larger data
func TestLargeFile(t *testing.T) {
	rs := &RSync{
		BlockSize: 1024,
	}

	// Create 100KB of data
	targetData := bytes.Repeat([]byte("A"), 100*1024)
	target := bytes.NewReader(targetData)

	var sigCount int
	err := rs.CreateSignature(target, func(bl BlockHash) error {
		sigCount++
		return nil
	})

	if err != nil {
		t.Fatalf("CreateSignature failed: %v", err)
	}

	expectedBlocks := rs.BlockHashCount(len(targetData))
	if sigCount != expectedBlocks {
		t.Errorf("Expected %d blocks, got %d", expectedBlocks, sigCount)
	}
}

// BenchmarkCreateSignature benchmarks signature creation
func BenchmarkCreateSignature(b *testing.B) {
	rs := &RSync{
		BlockSize: DefaultBlockSize,
	}

	data := bytes.Repeat([]byte("benchmark data "), 10000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		reader := bytes.NewReader(data)
		rs.CreateSignature(reader, func(bl BlockHash) error {
			return nil
		})
	}
}

// BenchmarkBetaHash benchmarks the rolling hash function
func BenchmarkBetaHash(b *testing.B) {
	data := []byte("The quick brown fox jumps over the lazy dog")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		βhash(data)
	}
}

// TestBuiltinMin tests that built-in min function works (Go 1.21+)
func TestBuiltinMin(t *testing.T) {
	result := min(5, 10)
	if result != 5 {
		t.Errorf("min(5, 10) = %d, expected 5", result)
	}

	result = min(100, 50)
	if result != 50 {
		t.Errorf("min(100, 50) = %d, expected 50", result)
	}
}
