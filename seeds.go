package gofuzzheaders

import (
	"bytes"
	"fmt"
	"reflect"
)

//
// Public API
//

type SeedPolicy struct {
	StringLen       int
	SliceLen        int
	MapLen          int
	IncludeOptional bool // include optional (omitempty) fields?
	PopulateAll     bool // allocate pointers when considered?
}

func DefaultSeedPolicy() SeedPolicy {
	return SeedPolicy{
		StringLen:       10,
		SliceLen:        2,
		MapLen:          2,
		IncludeOptional: true,
		PopulateAll:     true,
	}
}

// BuildSeedForTypes builds a deterministic seed byte slice sufficient for the
// Consumer to populate the given types exactly (given a matching Config).
func BuildSeedForTypes(cfg Config, pol SeedPolicy, types ...reflect.Type) ([]byte, error) {
	if len(types) == 0 {
		return nil, fmt.Errorf("BuildSeedForTypes: no types provided")
	}
	normalizePolicy(&pol, cfg)
	sb := &seedBuilder{cfg: cfg, pol: pol}
	for _, t := range types {
		if t == nil {
			return nil, fmt.Errorf("BuildSeedForTypes: nil type in inputs")
		}
		if err := sb.encodeValue(t, 0); err != nil {
			return nil, err
		}
	}
	return sb.output, nil
}

// BuildSeedForValues is a convenience wrapper that accepts values (or pointers).
func BuildSeedForValues(cfg Config, pol SeedPolicy, vals ...interface{}) ([]byte, error) {
	if len(vals) == 0 {
		return nil, fmt.Errorf("BuildSeedForValues: no values provided")
	}
	normalizePolicy(&pol, cfg)
	types := make([]reflect.Type, 0, len(vals))
	for i, v := range vals {
		if v == nil {
			return nil, fmt.Errorf("BuildSeedForValues: nil at index %d", i)
		}
		t := reflect.TypeOf(v)
		for t.Kind() == reflect.Ptr {
			t = t.Elem()
		}
		types = append(types, t)
	}
	return BuildSeedForTypes(cfg, pol, types...)
}

//
// Debug toggles (optional)
//

var seedDebug bool
var seedDbgBuf bytes.Buffer

// EnableSeedDebug enables/disables trace collection inside the seed encoder.
func EnableSeedDebug(v bool) {
	seedDebug = v
	if !v {
		seedDbgBuf.Reset()
	}
}

// SeedTrace returns the collected encoder trace (if enabled).
func SeedTrace() string {
	return seedDbgBuf.String()
}

func dbgf(format string, args ...interface{}) {
	if seedDebug {
		fmt.Fprintf(&seedDbgBuf, format, args...)
	}
}

//
// Internal implementation
//

type seedBuilder struct {
	cfg    Config
	pol    SeedPolicy
	output []byte
}

func normalizePolicy(pol *SeedPolicy, cfg Config) {
	if pol.StringLen <= 0 {
		pol.StringLen = 10
	}
	if pol.SliceLen < 0 {
		pol.SliceLen = 0
	}
	if pol.MapLen < 0 {
		pol.MapLen = 0
	}
	if pol.StringLen > cfg.MaxStringLen {
		pol.StringLen = cfg.MaxStringLen
	}
	if pol.SliceLen > cfg.MaxSliceLen {
		pol.SliceLen = cfg.MaxSliceLen
	}
	if pol.MapLen > cfg.MaxMapLen {
		pol.MapLen = cfg.MaxMapLen
	}
}

// ----- raw emitters -----

func (sb *seedBuilder) putByte(b byte) {
	sb.output = append(sb.output, b)
}

func (sb *seedBuilder) putU32(u uint32) {
	sb.output = append(sb.output, byte(u), byte(u>>8), byte(u>>16), byte(u>>24))
}

func (sb *seedBuilder) putU64(u uint64) {
	sb.output = append(sb.output,
		byte(u), byte(u>>8), byte(u>>16), byte(u>>24),
		byte(u>>32), byte(u>>40), byte(u>>48), byte(u>>56))
}

// IMPORTANT: In this Consumer, Continue()/ReadBool() returns true for NON-ZERO.
// So encode: true => 0x01; false => 0x00.
func (sb *seedBuilder) bTrue() byte  { return 0x01 }
func (sb *seedBuilder) bFalse() byte { return 0x00 }

// For ReadLen(max) which returns b % (max+1)
func (sb *seedBuilder) lenByte(max, want int) byte {
	if max < 0 {
		max = 0
	}
	if want < 0 {
		want = 0
	}
	if want > max {
		want = max
	}
	return byte(want % (max + 1))
}

// ----- deterministic primitives -----

func (sb *seedBuilder) encodePrimitive(t reflect.Type) error {
	switch t.Kind() {
	case reflect.Bool:
		sb.putByte(sb.bTrue()) // true
		dbgf("  prim bool -> true\n")
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		sb.putU64(0x1122334455667788)
		dbgf("  prim int* -> 0x1122334455667788\n")
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		sb.putU64(0x8877665544332211)
		dbgf("  prim uint* -> 0x8877665544332211\n")
		return nil
	case reflect.Float32:
		sb.putU32(123456789)
		dbgf("  prim float32 -> 123456789(u32)\n")
		return nil
	case reflect.Float64:
		sb.putU64(9876543210)
		dbgf("  prim float64 -> 9876543210(u64)\n")
		return nil
	case reflect.String:
		n := min(sb.pol.StringLen, sb.cfg.MaxStringLen)
		sb.putByte(sb.lenByte(sb.cfg.MaxStringLen, n))
		for i := 0; i < n; i++ {
			sb.putByte(byte('a' + (i % 26))) // "abcdefghij..."
		}
		dbgf("  prim string -> len=%d, ascii a.. pattern\n", n)
		return nil
	}
	return fmt.Errorf("encodePrimitive: unsupported kind %v", t.Kind())
}

func (sb *seedBuilder) encodeBytes(lenWant int) {
	n := min(lenWant, sb.cfg.MaxStringLen)
	sb.putByte(sb.lenByte(sb.cfg.MaxStringLen, n))
	for i := 0; i < n; i++ {
		sb.putByte(byte(i*17 + 3)) // 3,20,37,...
	}
	dbgf("  bytes [] -> len=%d, pattern 3,20,37,...\n", n)
}

// ----- containers -----

// encodeSlice writes a deterministic slice.
// - For []byte: write exactly cfg/policy bytes (no length prefix the consumer wouldn’t expect).
// - For other slices: write length first, then elements in order.
// - If element is a pointer: inline the pointee payload (no alloc/gates), same rule as for fields.
func (sb *seedBuilder) encodeSlice(t reflect.Type, depth int) error {
	elem := t.Elem()

	// []byte case
	if elem.Kind() == reflect.Uint8 {
		sb.encodeBytes(sb.pol.StringLen)
		return nil
	}

	// fixed deterministic length
	n := 2
	dbgf("  slice len=%d of %v\n", n, elem)
	sb.putByte(byte(n))

	for i := 0; i < n; i++ {
		switch elem.Kind() {
		case reflect.Ptr:
			poi := elem.Elem()
			dbgf("  slice elem ptr -> inline *%v (no gates/alloc)\n", poi)

			if isPrimitiveKind(poi.Kind()) {
				if err := sb.encodePrimitive(poi); err != nil {
					return err
				}
			} else {
				switch poi.Kind() {
				case reflect.Struct:
					if err := sb.encodeStruct(poi, depth+1); err != nil {
						return err
					}
				case reflect.Slice:
					if poi.Elem().Kind() == reflect.Uint8 {
						sb.encodeBytes(sb.pol.StringLen)
					} else if err := sb.encodeSlice(poi, depth+1); err != nil {
						return err
					}
				case reflect.Map:
					if err := sb.encodeMap(poi, depth+1); err != nil {
						return err
					}
				default:
					if err := sb.encodeValue(poi, depth+1); err != nil {
						return err
					}
				}
			}
		default:
			if err := sb.encodeValue(elem, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}



func (sb *seedBuilder) encodeMap(t reflect.Type, depth int) error {
	n := min(sb.pol.MapLen, sb.cfg.MaxMapLen)
	sb.putByte(sb.lenByte(sb.cfg.MaxMapLen, n))
	dbgf("  map len=%d of [%v]%v\n", n, t.Key(), t.Elem())
	for i := 0; i < n; i++ {
		if err := sb.encodeValue(t.Key(), depth+1); err != nil {
			return err
		}
		if err := sb.encodeValue(t.Elem(), depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (sb *seedBuilder) encodePtr(t reflect.Type, depth int) error {
	elem := t.Elem()
	dbgf("  -> ptr *%v\n", elem)

	// IMPORTANT: Do NOT emit pointee-level gates here.
	// Optional pointer fields already wrote:
	//   - optional presence
	//   - field-level populate (Ptr)
	//   - allocate
	// Consumers then expect the pointee payload immediately.

	return sb.encodeValue(elem, depth+1)
}

// ----- struct encoding aligned with Consumer.GenerateStruct -----
//
// Per field order (IMPORTANT):
//
//	(1) Field gate: Continue()?                    -> emit 0x01 (true)
//	(2) Optional presence (if optional): ReadBool  -> emit 0x01 (present) or 0x00 (absent)
//	(3) Payload in the order Consumer expects:
//	    - Ptr: allocate bool (0x01 allocate) then pointee payload
//	    - Slice/Map: length then entries
//	    - Struct: recurse (each child field repeats its own (1)/(2))
//	    - Primitives/String: direct payload
//
// NOTE: We DO NOT emit an extra "populate" bool for non-pointers (it caused misalignment).
func (sb *seedBuilder) encodeStruct(t reflect.Type, depth int) error {
    tm := getTypeMeta(t, sb.cfg, false)
    dbgf("struct %v {fields=%d}\n", t, len(tm.fields))

    for _, f := range tm.fields {
        // (1) Per-field gate
        sb.putByte(sb.bTrue())
        dbgf(" field gate -> true (kind=%v typ=%v optional=%v)\n", f.kind, f.typ, f.optional)

        // (2) Optional presence (json:",omitempty")
        if f.optional {
            if sb.pol.IncludeOptional {
                sb.putByte(sb.bTrue())
                dbgf("  optional present -> true\n")
            } else {
                sb.putByte(sb.bFalse())
                dbgf("  optional present -> false (skip payload)\n")
                continue
            }
        }

        // (3) NO field-level populate for Struct or Ptr anymore.
        //     (Ptr logic handles inlining inside the switch; Struct recurses directly.)

        // (4) Payload
        switch f.kind {
        case reflect.Ptr:
            elem := f.typ.Elem()
            if isPrimitiveKind(elem.Kind()) {
                dbgf("  ptr-to-primitive: inline payload (no gates/alloc)\n")
                if err := sb.encodePrimitive(elem); err != nil { return err }
                break
            }
            // Non-primitive pointee: inline payload directly (no ptr control bytes)
            switch elem.Kind() {
            case reflect.Struct:
                dbgf("  ptr-to-struct: inline payload (no gates/alloc/pointee-gates)\n")
                if err := sb.encodeStruct(elem, depth+1); err != nil { return err }
            case reflect.Slice:
    if f.elemType.Kind() == reflect.Uint8 {
        sb.encodeBytes(sb.pol.StringLen)
    } else if err := sb.encodeSlice(f.typ, depth+1); err != nil { return err }
            case reflect.Map:
                dbgf("  ptr-to-map: inline payload (no gates/alloc)\n")
                if err := sb.encodeMap(elem, depth+1); err != nil { return err }
            default:
                dbgf("  ptr-to-%v: inline payload (no gates/alloc)\n", elem.Kind())
                if err := sb.encodeValue(elem, depth+1); err != nil { return err }
            }

        case reflect.Map:
            if err := sb.encodeMap(f.typ, depth+1); err != nil { return err }

        case reflect.Slice:
            if f.elemType.Kind() == reflect.Uint8 {
                sb.encodeBytes(sb.pol.StringLen)
            } else if err := sb.encodeSlice(f.typ, depth+1); err != nil { return err }

        case reflect.Struct:
            // 👈 Recurse directly, no "populate (Struct)" byte
            if err := sb.encodeStruct(f.typ, depth+1); err != nil { return err }

        default:
            if err := sb.encodePrimitive(f.typ); err != nil { return err }
        }
    }
    return nil
}


func (sb *seedBuilder) encodeValue(t reflect.Type, depth int) error {
	if depth >= sb.cfg.MaxDepth {
		dbgf("depth %d >= MaxDepth %d, stop\n", depth, sb.cfg.MaxDepth)
		return nil
	}
	switch t.Kind() {
	case reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64, reflect.String:
		return sb.encodePrimitive(t)

	case reflect.Slice:
		if t.Elem().Kind() == reflect.Uint8 {
			sb.encodeBytes(sb.pol.StringLen)
			return nil
		}
		return sb.encodeSlice(t, depth+1)

	case reflect.Map:
		return sb.encodeMap(t, depth+1)

	case reflect.Ptr:
		// Top-level pointer value: mirror pointer field behavior.
		if sb.pol.PopulateAll {
			sb.putByte(sb.bTrue()) // allocate
			dbgf("toplevel ptr allocate -> true\n")
			return sb.encodePtr(t, depth+1)
		}
		sb.putByte(sb.bFalse())
		dbgf("toplevel ptr allocate -> false (nil)\n")
		return nil

	case reflect.Struct:
		return sb.encodeStruct(t, depth+1)
	}
	return nil
}

// ----- helpers -----

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func isPrimitiveKind(k reflect.Kind) bool {
	switch k {
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.String:
		return true
	default:
		return false
	}
}