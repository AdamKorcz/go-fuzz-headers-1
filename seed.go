package gofuzzheaders

import (
	"bytes"
	//"fmt"
	"reflect"
	//"unsafe"
	"strings"
)

type SeedGenerator struct {
	curDepth             int
	b *bytes.Buffer
}

func NewSeedGenerator() *SeedGenerator {
	by := make([]byte, 0)
	b := bytes.NewBuffer(by)
	return &SeedGenerator{
		b: b,
	}
}
func (f *SeedGenerator) GenerateSeed(targetStruct interface{}) ([]byte) {
	f.GenerateStruct(targetStruct)
	return f.b.Bytes()
}

func (f *SeedGenerator) GenerateStruct(targetStruct interface{}) error {
	e := reflect.ValueOf(targetStruct).Elem()
	f.fuzzStruct(e, false)
	return nil
}

func (f *SeedGenerator) fuzzStruct(e reflect.Value, customFunctions bool) error {
	if f.curDepth >= maxDepth {
		// return err or nil here?
		return nil
	}
	f.curDepth++
	defer func() { f.curDepth-- }()

	switch e.Kind() {
	case reflect.Struct:
		for i := 0; i < e.NumField(); i++ {
			//fmt.Println("Field:")
			if i == 30 {
				//fmt.Println(f.b.Bytes())
				//panic("Stop here")
			}
			var v reflect.Value
			//fmt.Printf("%s: \n", e.Type().Field(i).Name)

			jsonTag := e.Type().Field(i).Tag.Get("json")
			if strings.Contains(jsonTag, ",omitempty") {
				// do not skip:
				f.b.Write([]byte{0x01})
			}

			if !e.Field(i).CanSet() {
				if err := f.fuzzStruct(v, customFunctions); err != nil {
					return err
				}
			} else {
				v = e.Field(i)
				if err := f.fuzzStruct(v, customFunctions); err != nil {
					return err
				}
			}
		}
	case reflect.String:
		_, err := f.GetString()
		if err != nil {
			return err
		}
	case reflect.Slice:
		var maxElements uint32
		// Byte slices should not be restricted
		if e.Type().String() == "[]uint8" {
			maxElements = 10000000
		} else {
			maxElements = 50
		}

		// Need uint32(2)
		randQty, err := f.GetUint32()
		if err != nil {
			return err
		}

		numOfElements := randQty % maxElements

		uu := reflect.MakeSlice(e.Type(), int(numOfElements), int(numOfElements))

		for i := 0; i < int(numOfElements); i++ {
			// If we have more than 10, then we can proceed with that.
			if err := f.fuzzStruct(uu.Index(i), customFunctions); err != nil {
				
			}
		}
		if e.CanSet() {
			e.Set(uu)
		}
	case reflect.Uint16:
		_, err := f.GetUint16()
		if err != nil {
			return err
		}
	case reflect.Uint32:
		_, err := f.GetUint32()
		if err != nil {
			return err
		}
	case reflect.Uint64:
		_, err := f.GetInt()
		if err != nil {
			return err
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		_, err := f.GetInt()
		if err != nil {
			return err
		}
	case reflect.Float32:
		_, err := f.GetFloat32()
		if err != nil {
			return err
		}
	case reflect.Float64:
		_, err := f.GetFloat64()
		if err != nil {
			return err
		}
	case reflect.Map:
		if e.CanSet() {
			e.Set(reflect.MakeMap(e.Type()))
			const maxElements = 50

			// int(2):
			f.b.Write([]byte{0x02})

			randQty := 2

			numOfElements := randQty % maxElements
			for i := 0; i < numOfElements; i++ {
				if i == 2 {

				}
				key := reflect.New(e.Type().Key()).Elem()
				if err := f.fuzzStruct(key, customFunctions); err != nil {
					return err
				}
				val := reflect.New(e.Type().Elem()).Elem()
				if err := f.fuzzStruct(val, customFunctions); err != nil {
					return err
				}
			}
		}
	case reflect.Ptr:
		if e.CanSet() {
			e.Set(reflect.New(e.Type().Elem()))
			if err := f.fuzzStruct(e.Elem(), customFunctions); err != nil {
				return err
			}
			return nil
		}
	case reflect.Uint8:
		_, err := f.GetByte()
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *SeedGenerator) GetStringArray() (reflect.Value, error) {
	return reflect.Value{}, nil
}

func (f *SeedGenerator) GetInt() (int, error) {
	//int(5):
	f.b.Write([]byte{0x35}) // 5
	return int(byte(0x35)), nil
}
func (f *SeedGenerator) GetByte() (byte, error) {
	// "a":
	f.b.Write([]byte{0x61})
	return byte(0x61), nil
}

// Not used for Structs
func (f *SeedGenerator) GetNBytes(numberOfBytes int) ([]byte, error) {
	return []byte{0x00}, nil
}

func (f *SeedGenerator) GetUint16() (uint16, error) {
	// should be uint16(2)
	f.b.Write([]byte{0x00, 0x02})
	return uint16(2), nil
}
func (f *SeedGenerator) GetUint32() (uint32, error) {
	// should be uint32(2)
	f.b.Write([]byte{0x00, 0x00, 0x00, 0x02})
	return uint32(2), nil
}
func (f *SeedGenerator) GetUint64() (uint64, error) {
	// should be uint32(2)
	f.b.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})
	return uint64(2), nil
}
func (f *SeedGenerator) GetBytes() ([]byte, error) {
	f.b.Write([]byte{0x00, 0x00, 0x00, 0x03}) // length
	f.b.Write([]byte{0x41,0x42,0x43})
	return []byte{0x00}, nil
}


func (f *SeedGenerator) GetString() (string, error) {
	//fmt.Println("Writing string")
	f.b.Write([]byte{0x00, 0x00, 0x00, 0x03}) // length
	f.b.Write([]byte{0x41,0x42,0x43})
	return "ABC", nil
}


func (f *SeedGenerator) GetBool() (bool, error) {
	// true:
	f.b.Write([]byte{0x00})
	return true, nil
}

// Not needed
func (f *SeedGenerator) FuzzMap(m interface{}) error { return nil }
func (f *SeedGenerator) TarBytes() ([]byte, error) { return []byte{0x00}, nil }
func (f *SeedGenerator) TarFiles() ([]*TarFile, error) {
	return []*TarFile{nil}, nil
}
func (f *SeedGenerator) CreateFiles(rootDir string) error { return nil }
func (f *SeedGenerator) GetStringFrom(possibleChars string, length int) (string, error) { return "", nil }
func (f *SeedGenerator) GetRune() ([]rune, error) {
	s := ""
	return []rune(s), nil
}
func (f *SeedGenerator) GetFloat32() (float32, error) {
	f.b.Write([]byte{0x00, 0x00, 0x00, 0x04})
	f.b.Write([]byte{0x01}) // little endian: false
	return float32(0), nil
}
func (f *SeedGenerator) GetFloat64() (float64, error) {
	f.b.Write([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04})	
	f.b.Write([]byte{0x01}) // little endian: false
	return float64(0), nil
}
func (f *SeedGenerator) CreateSlice(targetSlice interface{}) error { return nil }