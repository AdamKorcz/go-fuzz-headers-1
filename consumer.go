package gofuzzheaders

import (
	"encoding/binary"
	"errors"
	"hash/fnv"
	"math"
	"reflect"
	"strings"
	"sync"
)

////////////////////////////////////////////////////////////////////////////////
// Reader — single-cursor, safe, deterministic
////////////////////////////////////////////////////////////////////////////////

type Reader struct {
	b   []byte
	off int
}

func NewReader(b []byte) Reader  { return Reader{b: b} }
func (r *Reader) Remaining() int { return len(r.b) - r.off }

func (r *Reader) ReadByte() (byte, bool) {
	if r.off >= len(r.b) {
		return 0, false
	}
	v := r.b[r.off]
	r.off++
	return v, true
}

func (r *Reader) ReadBool() (bool, bool) {
	b, ok := r.ReadByte()
	if !ok {
		return false, false
	}
	return (b & 1) == 1, true
}

func (r *Reader) ReadBytesN(n int) ([]byte, bool) {
	if n < 0 || r.off+n > len(r.b) {
		return nil, false
	}
	s := r.b[r.off : r.off+n]
	r.off += n
	return s, true
}

func (r *Reader) ReadUint64LE() (uint64, bool) {
	if r.Remaining() < 8 {
		return 0, false
	}
	bs, _ := r.ReadBytesN(8)
	return binary.LittleEndian.Uint64(bs), true
}

func (r *Reader) ReadUint32LE() (uint32, bool) {
	if r.Remaining() < 4 {
		return 0, false
	}
	bs, _ := r.ReadBytesN(4)
	return binary.LittleEndian.Uint32(bs), true
}

func (r *Reader) ReadLen(max int) (int, bool) {
	if max <= 0 {
		return 0, true
	}
	b, ok := r.ReadByte()
	if !ok {
		return 0, false
	}
	return int(b) % (max + 1), true
}

////////////////////////////////////////////////////////////////////////////////
// Config
////////////////////////////////////////////////////////////////////////////////

type Config struct {
	MaxDepth             int
	MaxSliceLen          int
	MaxMapLen            int
	MaxStringLen         int
	OptionalPresentNum   int
	OptionalPresentDenom int
	ContainersOptional   bool
}

func DefaultConfig() Config {
	return Config{
		MaxDepth:             5,
		MaxSliceLen:          16,
		MaxMapLen:            8,
		MaxStringLen:         64,
		OptionalPresentNum:   2, // ~2/3 present
		OptionalPresentDenom: 3,
		ContainersOptional:   true,
	}
}

////////////////////////////////////////////////////////////////////////////////
// ConsumeFuzzer — keep Funcs for custom generators (funcs.go depends on it)
////////////////////////////////////////////////////////////////////////////////

type ConsumeFuzzer struct {
	r     Reader
	cfg   Config
	Funcs map[reflect.Type]reflect.Value

	allowUnexported bool
}

func NewConsumer(b []byte) *ConsumeFuzzer {
	return &ConsumeFuzzer{r: NewReader(b), cfg: DefaultConfig(), Funcs: make(map[reflect.Type]reflect.Value)}
}

func NewConsumerWithConfig(b []byte, cfg Config) *ConsumeFuzzer {
	return &ConsumeFuzzer{r: NewReader(b), cfg: cfg, Funcs: make(map[reflect.Type]reflect.Value)}
}

func (cf *ConsumeFuzzer) RemainingBytes() int { return cf.r.Remaining() }

func (cf *ConsumeFuzzer) AllowUnexportedFields()    { cf.allowUnexported = true }
func (cf *ConsumeFuzzer) DisallowUnexportedFields() { cf.allowUnexported = false }

////////////////////////////////////////////////////////////////////////////////
// Primitive Get* — preserve original names
////////////////////////////////////////////////////////////////////////////////

func (cf *ConsumeFuzzer) GetBool() (bool, error) {
	b, ok := cf.r.ReadBool()
	if !ok {
		return false, errors.New("no bytes left")
	}
	return b, nil
}

func (cf *ConsumeFuzzer) GetInt() (int, error) {
	u, ok := cf.r.ReadUint64LE()
	if !ok {
		return 0, errors.New("no bytes left")
	}
	return int(int64(u)), nil
}

func (cf *ConsumeFuzzer) GetUint() (uint, error) {
	u, ok := cf.r.ReadUint64LE()
	if !ok {
		return 0, errors.New("no bytes left")
	}
	return uint(u), nil
}

// GetUint32 returns a uint32 read from the fuzzer's input in little-endian order.
// If there are not enough bytes left, it returns an error and does not panic.
// This matches the style of GetUint(), GetInt(), etc.
func (cf *ConsumeFuzzer) GetUint32() (uint32, error) {
	u, ok := cf.r.ReadUint32LE()
	if !ok {
		return 0, errors.New("no bytes left")
	}
	return u, nil
}

func (cf *ConsumeFuzzer) GetFloat32() (float32, error) {
	u, ok := cf.r.ReadUint32LE()
	if !ok {
		return 0, errors.New("no bytes left")
	}
	f := float64(int32(u%200000)) / 1000.0
	return float32(sanitizeFloat64(f)), nil
}

func (cf *ConsumeFuzzer) GetFloat64() (float64, error) {
	u, ok := cf.r.ReadUint64LE()
	if !ok {
		return 0, errors.New("no bytes left")
	}
	f := float64(int64(u%200000)) / 1000.0
	return sanitizeFloat64(f), nil
}

func (cf *ConsumeFuzzer) GetString() (string, error) {
	n, ok := cf.r.ReadLen(cf.cfg.MaxStringLen)
	if !ok || n == 0 || cf.r.Remaining() < n {
		return "", errors.New("no bytes left for string")
	}
	bs, ok := cf.r.ReadBytesN(n)
	if !ok {
		return "", errors.New("no bytes left for string")
	}
	out := make([]byte, n)
	for i := range bs {
		b := bs[i]
		if b < 32 || b > 126 {
			b = 'a' + (b % 26)
		}
		out[i] = b
	}
	return string(out), nil
}

func (cf *ConsumeFuzzer) GetBytes() ([]byte, error) {
	n, ok := cf.r.ReadLen(cf.cfg.MaxStringLen)
	if !ok || n == 0 || cf.r.Remaining() < n {
		return nil, errors.New("no bytes left for bytes")
	}
	bs, ok := cf.r.ReadBytesN(n)
	if !ok {
		return nil, errors.New("no bytes left for bytes")
	}
	out := make([]byte, n)
	copy(out, bs)
	return out, nil
}

////////////////////////////////////////////////////////////////////////////////
// Reflection metadata & helpers
////////////////////////////////////////////////////////////////////////////////

type fieldMeta struct {
	index    int
	kind     reflect.Kind
	typ      reflect.Type
	elemType reflect.Type
	keyType  reflect.Type
	isPtr    bool
	optional bool
	exported bool
	jsonSkip bool
}

type typeMeta struct {
	t      reflect.Type
	typeID uint64
	fields []fieldMeta
}

var typeCache sync.Map

func getTypeMeta(t reflect.Type, cfg Config, allowUnexported bool) *typeMeta {
	if v, ok := typeCache.Load(t); ok {
		return v.(*typeMeta)
	}
	m := &typeMeta{t: t, typeID: hashType(t)}
	n := t.NumField()
	for i := 0; i < n; i++ {
		f := t.Field(i)

		exported := (f.PkgPath == "")
		if !exported && !allowUnexported {
			continue
		}

		tag := f.Tag.Get("json")
		jsonSkip := false
		omitempty := false
		if tag != "" {
			parts := strings.Split(tag, ",")
			for _, p := range parts {
				if p == "-" {
					jsonSkip = true
					break
				}
				if p == "omitempty" {
					omitempty = true
				}
			}
		}
		if jsonSkip {
			continue
		}

		fm := fieldMeta{
			index:    f.Index[0],
			kind:     f.Type.Kind(),
			typ:      f.Type,
			isPtr:    f.Type.Kind() == reflect.Ptr,
			optional: omitempty,
			exported: exported,
			jsonSkip: jsonSkip,
		}
		switch f.Type.Kind() {
		case reflect.Ptr, reflect.Slice, reflect.Array:
			fm.elemType = f.Type.Elem()
		case reflect.Map:
			fm.elemType = f.Type.Elem()
			fm.keyType = f.Type.Key()
		}
		if cfg.ContainersOptional && (fm.isPtr || fm.kind == reflect.Slice || fm.kind == reflect.Map) {
			fm.optional = true || fm.optional
		}
		m.fields = append(m.fields, fm)
	}
	typeCache.Store(t, m)
	return m
}

func hashType(t reflect.Type) uint64 {
	h := fnv.New64a()
	h.Write([]byte(t.PkgPath()))
	h.Write([]byte{0})
	h.Write([]byte(t.Name()))
	return h.Sum64()
}

func stablePresent(typeID uint64, fieldIndex int) bool {
	// Deterministic decision without reading bytes.
	x := typeID ^ uint64(0x9E3779B185EBCA87*uint64(fieldIndex+1))
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	return (x & 1) == 1
}

////////////////////////////////////////////////////////////////////////////////
// Public fuzzing entry points required by other files in the repo
////////////////////////////////////////////////////////////////////////////////

// ensureStructPtr dereferences rv through any number of pointers,
// allocating along the way, and returns the underlying struct value.
func ensureStructPtr(rv reflect.Value) (reflect.Value, error) {
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return reflect.Value{}, errors.New("target must be a non-nil pointer")
	}
	// Walk pointer chain, allocating as needed.
	for rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			rv.Set(reflect.New(rv.Type().Elem()))
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return reflect.Value{}, errors.New("target does not resolve to a struct")
	}
	return rv, nil
}

// ensureMapPtr dereferences rv through any number of pointers,
// allocating along the way, and returns the underlying map value.
func ensureMapPtr(rv reflect.Value) (reflect.Value, error) {
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return reflect.Value{}, errors.New("map target must be a non-nil pointer")
	}
	for rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			rv.Set(reflect.New(rv.Type().Elem()))
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Map {
		return reflect.Value{}, errors.New("map target does not resolve to a map")
	}
	// Ensure non-nil map
	if rv.IsNil() {
		rv.Set(reflect.MakeMapWithSize(rv.Type(), 0))
	}
	return rv, nil
}

func (cf *ConsumeFuzzer) GenerateStruct(target interface{}) error {
	if target == nil {
		return errors.New("nil target")
	}
	rv, err := ensureStructPtr(reflect.ValueOf(target))
	if err != nil {
		return err
	}
	// withCustom=true so funcs.go hooks still run
	return cf.fuzzStruct(rv, true)
}

// FuzzMap allows repo helpers (e.g., inject_fuzzer.go) to populate a map directly.
func (cf *ConsumeFuzzer) FuzzMap(target interface{}) error {
	if target == nil {
		return errors.New("nil target map")
	}
	mv, err := ensureMapPtr(reflect.ValueOf(target))
	if err != nil {
		return err
	}
	// Build minimal field meta and populate.
	f := fieldMeta{
		kind:     reflect.Map,
		typ:      mv.Type(),
		elemType: mv.Type().Elem(),
		keyType:  mv.Type().Key(),
	}
	cf.populateMap(mv, f, 0, true)
	return nil
}

// fuzzStruct is the internal worker expected by funcs.go (withCustom toggles custom funcs)
func (cf *ConsumeFuzzer) fuzzStruct(rv reflect.Value, withCustom bool) error {
	cf.populateStruct(rv, 0, withCustom)
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// Population implementing the 3 rules
////////////////////////////////////////////////////////////////////////////////

func (cf *ConsumeFuzzer) populateStruct(rv reflect.Value, depth int, withCustom bool) {
	if depth >= cf.cfg.MaxDepth {
		return
	}
	tm := getTypeMeta(rv.Type(), cf.cfg, cf.allowUnexported)

	for _, f := range tm.fields {
		fv := rv.Field(f.index)

		// Rule 1: presence decision
		present := true
		if f.optional {
			if cf.r.Remaining() > 0 {
				// one byte presence with bias
				b, _ := cf.r.ReadByte()
				den := cf.cfg.OptionalPresentDenom
				num := cf.cfg.OptionalPresentNum
				if den <= 0 {
					present = true
				} else {
					present = (int(b) % den) < num
				}
			} else {
				// exhausted → stable, zero-read presence
				present = stablePresent(tm.typeID, f.index)
			}
		}
		if !present {
			continue
		}

		// Creation: non-nil containers when present
		switch f.kind {
		case reflect.Ptr:
			if fv.IsNil() {
				fv.Set(reflect.New(f.elemType))
			}
		case reflect.Map:
			if fv.IsNil() {
				fv.Set(reflect.MakeMapWithSize(f.typ, 0))
			}
		case reflect.Slice:
			if fv.IsNil() {
				fv.Set(reflect.MakeSlice(f.typ, 0, 0))
			}
		}

		// Rule 2/3: populate only if bytes remain
		if cf.r.Remaining() == 0 {
			continue // Rule 3: exhausted -> do not populate
		}
		doPopulate := false
		if b, ok := cf.r.ReadBool(); ok {
			doPopulate = b
		}
		if !doPopulate || cf.r.Remaining() == 0 {
			continue
		}

		// Custom funcs hook (funcs.go registers only for certain types)
		if withCustom && cf.Funcs != nil {
			if fn, recv := cf.lookupCustom(fv, f); fn.IsValid() {
				// call: fn(recv, Continue{F: cf}) — Continue is defined in funcs.go
				args := []reflect.Value{recv, reflect.ValueOf(Continue{F: cf})}
				outs := fn.Call(args)
				if len(outs) == 0 || (len(outs) == 1 && outs[0].IsNil()) {
					continue // handled
				}
				// If custom returned error, fall through to generic population.
			}
		}

		// Generic population
		switch f.kind {
		case reflect.Slice:
			cf.populateSlice(fv, f, depth+1, withCustom)
		case reflect.Map:
			cf.populateMap(fv, f, depth+1, withCustom)
		case reflect.Ptr:
			cf.populateValue(fv.Elem(), depth+1, withCustom)
		default:
			cf.populateValue(fv, depth+1, withCustom)
		}
	}
}

func (cf *ConsumeFuzzer) populateSlice(fv reflect.Value, f fieldMeta, depth int, withCustom bool) {
	if depth >= cf.cfg.MaxDepth || cf.r.Remaining() == 0 {
		return
	}
	n, ok := cf.r.ReadLen(minInt(cf.cfg.MaxSliceLen, 255))
	if !ok || n <= 0 {
		return
	}
	// Fast path for []byte
	if f.elemType.Kind() == reflect.Uint8 {
		if cf.r.Remaining() < n {
			return
		}
		bs, ok := cf.r.ReadBytesN(n)
		if !ok {
			return
		}
		out := make([]byte, n)
		copy(out, bs)
		fv.SetBytes(out)
		return
	}
	s := reflect.MakeSlice(f.typ, n, n)
	for i := 0; i < n && cf.r.Remaining() > 0; i++ {
		cf.populateValue(s.Index(i), depth+1, withCustom)
	}
	fv.Set(s)
}

func (cf *ConsumeFuzzer) populateMap(fv reflect.Value, f fieldMeta, depth int, withCustom bool) {
	if depth >= cf.cfg.MaxDepth || cf.r.Remaining() == 0 {
		return
	}
	n, ok := cf.r.ReadLen(minInt(cf.cfg.MaxMapLen, 127))
	if !ok || n <= 0 {
		return
	}
	for i := 0; i < n && cf.r.Remaining() > 0; i++ {
		kv := reflect.New(f.keyType).Elem()
		vv := reflect.New(f.elemType).Elem()
		cf.populateValue(kv, depth+1, withCustom)
		if cf.r.Remaining() == 0 {
			break
		}
		cf.populateValue(vv, depth+1, withCustom)
		fv.SetMapIndex(kv, vv)
	}
}

func (cf *ConsumeFuzzer) populateValue(v reflect.Value, depth int, withCustom bool) {
	if depth >= cf.cfg.MaxDepth || !v.CanSet() || cf.r.Remaining() == 0 {
		return
	}

	switch v.Kind() {
	case reflect.Bool:
		if b, ok := cf.r.ReadBool(); ok {
			v.SetBool(b)
		}

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if u, ok := cf.r.ReadUint64LE(); ok {
			setIntClamp(v, int64(u))
		}

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if u, ok := cf.r.ReadUint64LE(); ok {
			setUintClamp(v, u)
		}

	case reflect.Float32:
		if u, ok := cf.r.ReadUint32LE(); ok {
			f := float64(int32(u%200000)) / 1000.0
			v.SetFloat(float64(float32(f)))
		}

	case reflect.Float64:
		if u, ok := cf.r.ReadUint64LE(); ok {
			f := float64(int64(u%200000)) / 1000.0
			v.SetFloat(sanitizeFloat64(f))
		}

	case reflect.String:
		n, ok := cf.r.ReadLen(cf.cfg.MaxStringLen)
		if !ok || n == 0 || cf.r.Remaining() < n {
			return
		}
		bs, ok := cf.r.ReadBytesN(n)
		if !ok {
			return
		}
		out := make([]byte, n)
		for i := range bs {
			b := bs[i]
			if b < 32 || b > 126 {
				b = 'a' + (b % 26)
			}
			out[i] = b
		}
		v.SetString(string(out))

	case reflect.Slice:
		f := fieldMeta{typ: v.Type(), elemType: v.Type().Elem(), kind: v.Kind()}
		cf.populateSlice(v, f, depth+1, withCustom)

	case reflect.Map:
		f := fieldMeta{typ: v.Type(), elemType: v.Type().Elem(), keyType: v.Type().Key(), kind: v.Kind()}
		if v.IsNil() {
			v.Set(reflect.MakeMapWithSize(v.Type(), 0))
		}
		cf.populateMap(v, f, depth+1, withCustom)

	case reflect.Struct:
		cf.populateStruct(v, depth+1, withCustom)

	case reflect.Ptr:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		cf.populateValue(v.Elem(), depth+1, withCustom)

	case reflect.Interface:
		// Leave nil by default
	}
}

////////////////////////////////////////////////////////////////////////////////
// Custom funcs lookup (only if withCustom==true)
////////////////////////////////////////////////////////////////////////////////

func (cf *ConsumeFuzzer) lookupCustom(fv reflect.Value, f fieldMeta) (fn reflect.Value, recv reflect.Value) {
	if cf.Funcs == nil {
		return reflect.Value{}, reflect.Value{}
	}
	// Exact type first
	if fn, ok := cf.Funcs[fv.Type()]; ok {
		return fn, fv
	}
	// Pointer-to-field
	if fv.CanAddr() {
		if fn, ok := cf.Funcs[fv.Addr().Type()]; ok {
			// ensure pointer receiver is non-nil for ptr kinds
			if fv.Kind() == reflect.Ptr && fv.IsNil() {
				fv.Set(reflect.New(fv.Type().Elem()))
			}
			return fn, fv.Addr()
		}
	}
	// For pointer fields: try function registered on pointer type directly
	if f.isPtr {
		if fn, ok := cf.Funcs[f.typ]; ok {
			return fn, fv
		}
	}
	return reflect.Value{}, reflect.Value{}
}

////////////////////////////////////////////////////////////////////////////////
// Helpers
////////////////////////////////////////////////////////////////////////////////

func setIntClamp(v reflect.Value, x int64) {
	switch v.Kind() {
	case reflect.Int8:
		v.SetInt(int64(int8(x)))
	case reflect.Int16:
		v.SetInt(int64(int16(x)))
	case reflect.Int32:
		v.SetInt(int64(int32(x)))
	case reflect.Int, reflect.Int64:
		bits := v.Type().Bits()
		max := int64(1)<<(bits-1) - 1
		min := -max - 1
		if x > max {
			x = max
		} else if x < min {
			x = min
		}
		v.SetInt(x)
	}
}

func setUintClamp(v reflect.Value, x uint64) {
	switch v.Kind() {
	case reflect.Uint8:
		v.SetUint(uint64(uint8(x)))
	case reflect.Uint16:
		v.SetUint(uint64(uint16(x)))
	case reflect.Uint32:
		v.SetUint(uint64(uint32(x)))
	case reflect.Uint, reflect.Uint64, reflect.Uintptr:
		bits := v.Type().Bits()
		if bits < 64 {
			x &= (uint64(1) << bits) - 1
		}
		v.SetUint(x)
	}
}

func sanitizeFloat64(x float64) float64 {
	if math.IsNaN(x) || math.IsInf(x, 0) {
		return 0
	}
	return x
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
