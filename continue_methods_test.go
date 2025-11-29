package gofuzzheaders

import (
	"testing"
)

func TestContinueMethods(t *testing.T) {
	data := []byte("test data with enough bytes for fuzzing operations")
	cf := NewConsumer(data)
	c := Continue{F: cf}

	// Test Intn
	val := c.Intn(100)
	if val < 0 || val >= 100 {
		t.Errorf("Intn(100) returned %d, expected value in [0, 100)", val)
	}

	// Test RandBool
	_ = c.RandBool() // Just verify it doesn't panic

	// Test RandString
	str := c.RandString()
	if str == "" {
		t.Log("RandString returned empty string (expected when data is exhausted)")
	}

	// Test Int31
	_ = c.Int31() // Just verify it doesn't panic

	// Test Int63
	_ = c.Int63() // Just verify it doesn't panic

	// Test Uint32
	_ = c.Uint32() // Just verify it doesn't panic

	// Test Int
	_ = c.Int() // Just verify it doesn't panic

	t.Log("All Continue methods executed successfully")
}
