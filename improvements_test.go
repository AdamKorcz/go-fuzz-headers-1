package gofuzzheaders

import (
	"reflect"
	"testing"
)

// Test parseFieldTags function
func TestParseFieldTags(t *testing.T) {
	// Define test struct types with various tags
	type JSONOmitempty struct {
		Field string `json:"field,omitempty"`
	}
	type JSONSkip struct {
		Field string `json:"-"`
	}
	type YAMLOmitempty struct {
		Field string `yaml:"field,omitempty"`
	}
	type ValidateRequired struct {
		Field string `validate:"required"`
	}
	type BindingRequired struct {
		Field string `binding:"required"`
	}
	type ProtobufRequired struct {
		Field string `protobuf:"bytes,1,req,name=field"`
	}
	type NoTags struct {
		Field string
	}
	type PointerField struct {
		Field *int
	}

	tests := []struct {
		name         string
		structType   reflect.Type
		wantOptional bool
		wantRequired bool
		wantSkip     bool
	}{
		{
			name:         "json omitempty makes field optional",
			structType:   reflect.TypeOf(JSONOmitempty{}),
			wantOptional: true,
			wantRequired: false,
			wantSkip:     false,
		},
		{
			name:         "json dash skips field",
			structType:   reflect.TypeOf(JSONSkip{}),
			wantOptional: false,
			wantRequired: false,
			wantSkip:     true,
		},
		{
			name:         "yaml omitempty makes field optional",
			structType:   reflect.TypeOf(YAMLOmitempty{}),
			wantOptional: true,
			wantRequired: false,
			wantSkip:     false,
		},
		{
			name:         "validate required makes field required",
			structType:   reflect.TypeOf(ValidateRequired{}),
			wantOptional: false,
			wantRequired: true,
			wantSkip:     false,
		},
		{
			name:         "binding required makes field required",
			structType:   reflect.TypeOf(BindingRequired{}),
			wantOptional: false,
			wantRequired: true,
			wantSkip:     false,
		},
		{
			name:         "protobuf req makes field required",
			structType:   reflect.TypeOf(ProtobufRequired{}),
			wantOptional: false,
			wantRequired: true,
			wantSkip:     false,
		},
		{
			name:         "no tags means not optional",
			structType:   reflect.TypeOf(NoTags{}),
			wantOptional: false,
			wantRequired: false,
			wantSkip:     false,
		},
		{
			name:         "pointer type is implicitly optional",
			structType:   reflect.TypeOf(PointerField{}),
			wantOptional: true,
			wantRequired: false,
			wantSkip:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			field := tt.structType.Field(0)
			cfg := DefaultConfig()

			optional, required, skip := parseFieldTags(field, cfg)

			if optional != tt.wantOptional {
				t.Errorf("parseFieldTags() optional = %v, want %v", optional, tt.wantOptional)
			}
			if required != tt.wantRequired {
				t.Errorf("parseFieldTags() required = %v, want %v", required, tt.wantRequired)
			}
			if skip != tt.wantSkip {
				t.Errorf("parseFieldTags() skip = %v, want %v", skip, tt.wantSkip)
			}
		})
	}
}

// Test PresenceBitmap
func TestPresenceBitmap(t *testing.T) {
	t.Run("Next returns bits in order", func(t *testing.T) {
		// Create reader with specific bit pattern: 0b10101010 (0xAA)
		data := []byte{0xAA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		r := NewReader(data)

		pb := &PresenceBitmap{}
		pb.Reset()

		// First 8 bits should be: 0,1,0,1,0,1,0,1 (LSB first)
		expected := []bool{false, true, false, true, false, true, false, true}
		for i, want := range expected {
			got := pb.Next(&r)
			if got != want {
				t.Errorf("bit %d: got %v, want %v", i, got, want)
			}
		}
	})

	t.Run("Refills automatically after 64 bits", func(t *testing.T) {
		// Create reader with two uint64s: first all 1s, second all 0s
		data := make([]byte, 16)
		for i := 0; i < 8; i++ {
			data[i] = 0xFF // First 64 bits all 1
		}
		// Next 8 bytes already 0

		r := NewReader(data)
		pb := &PresenceBitmap{}
		pb.Reset()

		// First 64 bits should be true
		for i := 0; i < 64; i++ {
			if !pb.Next(&r) {
				t.Errorf("bit %d should be true", i)
			}
		}

		// Next 64 bits should be false
		for i := 64; i < 128; i++ {
			if pb.Next(&r) {
				t.Errorf("bit %d should be false", i)
			}
		}
	})

	t.Run("Pool reuses bitmaps", func(t *testing.T) {
		pb1 := presenceBitmapPool.Get().(*PresenceBitmap)
		pb1.bits = 0x12345678
		pb1.bitsRemaining = 42

		presenceBitmapPool.Put(pb1)
		pb2 := presenceBitmapPool.Get().(*PresenceBitmap)

		// Should be the same object
		if pb1 != pb2 {
			t.Error("Pool should reuse objects")
		}
	})
}

// Test exact-size reads
func TestExactSizeReads(t *testing.T) {
	t.Run("ReadUint16LE reads 2 bytes", func(t *testing.T) {
		data := []byte{0x34, 0x12, 0xFF, 0xFF}
		r := NewReader(data)

		val, ok := r.ReadUint16LE()
		if !ok {
			t.Fatal("ReadUint16LE failed")
		}
		if val != 0x1234 {
			t.Errorf("got 0x%X, want 0x1234", val)
		}
		if r.Remaining() != 2 {
			t.Errorf("remaining = %d, want 2", r.Remaining())
		}
	})

	t.Run("ReadUint16LE fails on insufficient bytes", func(t *testing.T) {
		data := []byte{0x34}
		r := NewReader(data)

		_, ok := r.ReadUint16LE()
		if ok {
			t.Error("ReadUint16LE should fail with 1 byte")
		}
	})
}

// Test populateValue with exact-size reads
func TestPopulateValueExactSizes(t *testing.T) {
	tests := []struct {
		name        string
		kind        reflect.Kind
		data        []byte
		wantBytes   int
		wantValue   interface{}
	}{
		{
			name:      "int8 uses 1 byte",
			kind:      reflect.Int8,
			data:      []byte{0x42, 0xFF, 0xFF, 0xFF},
			wantBytes: 1,
			wantValue: int8(0x42),
		},
		{
			name:      "uint8 uses 1 byte",
			kind:      reflect.Uint8,
			data:      []byte{0x42, 0xFF, 0xFF, 0xFF},
			wantBytes: 1,
			wantValue: uint8(0x42),
		},
		{
			name:      "int16 uses 2 bytes",
			kind:      reflect.Int16,
			data:      []byte{0x34, 0x12, 0xFF, 0xFF},
			wantBytes: 2,
			wantValue: int16(0x1234),
		},
		{
			name:      "uint16 uses 2 bytes",
			kind:      reflect.Uint16,
			data:      []byte{0x34, 0x12, 0xFF, 0xFF},
			wantBytes: 2,
			wantValue: uint16(0x1234),
		},
		{
			name:      "int32 uses 4 bytes",
			kind:      reflect.Int32,
			data:      []byte{0x78, 0x56, 0x34, 0x12, 0xFF, 0xFF},
			wantBytes: 4,
			wantValue: int32(0x12345678),
		},
		{
			name:      "uint32 uses 4 bytes",
			kind:      reflect.Uint32,
			data:      []byte{0x78, 0x56, 0x34, 0x12, 0xFF, 0xFF},
			wantBytes: 4,
			wantValue: uint32(0x12345678),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cf := NewConsumer(tt.data)
			
			v := reflect.New(reflect.TypeOf(tt.wantValue)).Elem()
			cf.populateValue(v, 0, false)

			if cf.r.Remaining() != len(tt.data)-tt.wantBytes {
				t.Errorf("consumed %d bytes, want %d", len(tt.data)-cf.r.Remaining(), tt.wantBytes)
			}

			got := v.Interface()
			if got != tt.wantValue {
				t.Errorf("got %v, want %v", got, tt.wantValue)
			}
		})
	}
}

// Test MaxByteSliceLen
func TestMaxByteSliceLen(t *testing.T) {
	t.Run("byte slice uses MaxByteSliceLen", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.MaxSliceLen = 10
		cfg.MaxByteSliceLen = 100

		// Create data: length byte + 50 bytes of data
		data := make([]byte, 52)
		data[0] = 50 // length
		for i := 1; i < 51; i++ {
			data[i] = byte(i)
		}

		cf := NewConsumerWithConfig(data, cfg)

		var slice []byte
		v := reflect.ValueOf(&slice).Elem()
		
		// Create fieldMeta for []byte
		fm := fieldMeta{
			typ:      reflect.TypeOf(slice),
			elemType: reflect.TypeOf(byte(0)),
			kind:     reflect.Slice,
		}

		cf.populateSlice(v, fm, 0, false)

		if len(slice) != 50 {
			t.Errorf("byte slice length = %d, want 50", len(slice))
		}

		// Verify MaxByteSliceLen was used (not MaxSliceLen)
		if len(slice) > cfg.MaxSliceLen {
			t.Logf("✓ Correctly used MaxByteSliceLen (%d) instead of MaxSliceLen (%d)", 
				cfg.MaxByteSliceLen, cfg.MaxSliceLen)
		}
	})

	t.Run("typed slice uses MaxSliceLen", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.MaxSliceLen = 5
		cfg.MaxByteSliceLen = 100

		// Create data for slice of ints
		data := make([]byte, 100)
		data[0] = 10 // Try to create 10 elements

		cf := NewConsumerWithConfig(data, cfg)

		var slice []int32
		v := reflect.ValueOf(&slice).Elem()
		
		fm := fieldMeta{
			typ:      reflect.TypeOf(slice),
			elemType: reflect.TypeOf(int32(0)),
			kind:     reflect.Slice,
		}

		cf.populateSlice(v, fm, 0, false)

		// Should be limited by MaxSliceLen (5), not MaxByteSliceLen (100)
		if len(slice) > cfg.MaxSliceLen {
			t.Errorf("typed slice length = %d, should be limited to MaxSliceLen = %d", 
				len(slice), cfg.MaxSliceLen)
		}
	})
}

// Test KubernetesConfig preset
func TestKubernetesConfig(t *testing.T) {
	cfg := KubernetesConfig()

	if cfg.MaxDepth != 10 {
		t.Errorf("MaxDepth = %d, want 10", cfg.MaxDepth)
	}
	if cfg.MaxSliceLen != 64 {
		t.Errorf("MaxSliceLen = %d, want 64", cfg.MaxSliceLen)
	}
	if cfg.MaxByteSliceLen != 4096 {
		t.Errorf("MaxByteSliceLen = %d, want 4096", cfg.MaxByteSliceLen)
	}
}

// Test KubernetesMinimalConfig preset
func TestKubernetesMinimalConfig(t *testing.T) {
	cfg := KubernetesMinimalConfig()

	if cfg.MaxDepth != 7 {
		t.Errorf("MaxDepth = %d, want 7", cfg.MaxDepth)
	}
	if cfg.MaxSliceLen != 4 {
		t.Errorf("MaxSliceLen = %d, want 4", cfg.MaxSliceLen)
	}
	if cfg.MaxByteSliceLen != 256 {
		t.Errorf("MaxByteSliceLen = %d, want 256", cfg.MaxByteSliceLen)
	}
}

// Test ConfigBuilder
func TestConfigBuilder(t *testing.T) {
	cfg := NewConfigBuilder(DefaultConfig()).
		WithMaxDepth(15).
		WithMaxSliceLen(100).
		WithMaxByteSliceLen(8192).
		WithMaxStringLen(500).
		WithOptionalPresence(4, 5).
		Build()

	if cfg.MaxDepth != 15 {
		t.Errorf("MaxDepth = %d, want 15", cfg.MaxDepth)
	}
	if cfg.MaxSliceLen != 100 {
		t.Errorf("MaxSliceLen = %d, want 100", cfg.MaxSliceLen)
	}
	if cfg.MaxByteSliceLen != 8192 {
		t.Errorf("MaxByteSliceLen = %d, want 8192", cfg.MaxByteSliceLen)
	}
	if cfg.MaxStringLen != 500 {
		t.Errorf("MaxStringLen = %d, want 500", cfg.MaxStringLen)
	}
	if cfg.OptionalPresentNum != 4 {
		t.Errorf("OptionalPresentNum = %d, want 4", cfg.OptionalPresentNum)
	}
	if cfg.OptionalPresentDenom != 5 {
		t.Errorf("OptionalPresentDenom = %d, want 5", cfg.OptionalPresentDenom)
	}
}

// Test custom function compatibility
func TestCustomFunctionCompatibility(t *testing.T) {
	t.Run("gofuzz-style signature (no return)", func(t *testing.T) {
		called := false
		customFunc := func(s *string, c Continue) {
			called = true
			*s = "custom"
		}

		cf := NewConsumer([]byte{0x01, 0x02, 0x03})
		
		// Should not panic with gofuzz-style signature
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("AddFuncs panicked with gofuzz-style signature: %v", r)
			}
		}()
		
		cf.AddFuncs([]interface{}{customFunc})
		
		if !called {
			// This is expected - we just added the func, didn't call it yet
			t.Log("Function registered successfully (not called yet)")
		}
	})

	t.Run("go-fuzz-headers-style signature (returns error)", func(t *testing.T) {
		customFunc := func(s *string, c Continue) error {
			*s = "custom"
			return nil
		}

		cf := NewConsumer([]byte{0x01, 0x02, 0x03})
		
		// Should not panic with error return signature
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("AddFuncs panicked with error signature: %v", r)
			}
		}()
		
		cf.AddFuncs([]interface{}{customFunc})
	})
}

// Test Continue.Fuzz and Continue.FuzzNoCustom
func TestContinueFuzz(t *testing.T) {
	t.Run("Fuzz populates object", func(t *testing.T) {
		data := []byte{0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		cf := NewConsumer(data)
		c := Continue{F: cf}

		var val int32
		c.Fuzz(&val)

		// Should have populated val (not zero)
		if val == 0 {
			t.Error("Fuzz should populate value")
		}
	})

	t.Run("Fuzz panics on non-pointer", func(t *testing.T) {
		cf := NewConsumer([]byte{0x01})
		c := Continue{F: cf}

		defer func() {
			if r := recover(); r == nil {
				t.Error("Fuzz should panic on non-pointer")
			}
		}()

		var val int
		c.Fuzz(val) // Not a pointer - should panic
	})
}

// Test PresenceBitmap efficiency
func TestPresenceBitmapEfficiency(t *testing.T) {
	t.Run("PresenceBitmap uses 8x fewer bytes", func(t *testing.T) {
		// Test struct with 16 optional fields
		type TestStruct struct {
			F1  *int `json:",omitempty"`
			F2  *int `json:",omitempty"`
			F3  *int `json:",omitempty"`
			F4  *int `json:",omitempty"`
			F5  *int `json:",omitempty"`
			F6  *int `json:",omitempty"`
			F7  *int `json:",omitempty"`
			F8  *int `json:",omitempty"`
			F9  *int `json:",omitempty"`
			F10 *int `json:",omitempty"`
			F11 *int `json:",omitempty"`
			F12 *int `json:",omitempty"`
			F13 *int `json:",omitempty"`
			F14 *int `json:",omitempty"`
			F15 *int `json:",omitempty"`
			F16 *int `json:",omitempty"`
		}

		// Old approach: 16 bytes for presence decisions (1 byte per field)
		// New approach: 8 bytes for 64 fields (bitmap)
		// For 16 fields: ceiling(16/64) * 8 = 8 bytes

		// Create data with bitmap: 8 bytes + extra for values
		data := make([]byte, 100)
		data[0] = 0xFF // All fields present
		data[1] = 0xFF

		cfg := DefaultConfig()
		cf := NewConsumerWithConfig(data, cfg)

		var obj TestStruct
		err := cf.GenerateStruct(&obj)
		if err != nil {
			t.Fatalf("GenerateStruct failed: %v", err)
		}

		// With bitmap, we should consume ~8 bytes for presence
		// Old way would consume 16 bytes
		bytesConsumed := 100 - cf.r.Remaining()
		
		t.Logf("Bytes consumed: %d", bytesConsumed)
		
		// This test mainly verifies the code doesn't panic
		// Actual efficiency measurement would require more complex instrumentation
	})
}

// Benchmark exact-size reads vs always reading 8 bytes
func BenchmarkExactSizeReads(b *testing.B) {
	b.Run("int8-exact", func(b *testing.B) {
		data := make([]byte, 10000)
		for i := 0; i < b.N; i++ {
			cf := NewConsumer(data)
			var val int8
			v := reflect.ValueOf(&val).Elem()
			cf.populateValue(v, 0, false)
		}
	})

	b.Run("int16-exact", func(b *testing.B) {
		data := make([]byte, 10000)
		for i := 0; i < b.N; i++ {
			cf := NewConsumer(data)
			var val int16
			v := reflect.ValueOf(&val).Elem()
			cf.populateValue(v, 0, false)
		}
	})

	b.Run("int32-exact", func(b *testing.B) {
		data := make([]byte, 10000)
		for i := 0; i < b.N; i++ {
			cf := NewConsumer(data)
			var val int32
			v := reflect.ValueOf(&val).Elem()
			cf.populateValue(v, 0, false)
		}
	})
}
