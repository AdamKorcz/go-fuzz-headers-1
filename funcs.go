// Copyright 2023 The go-fuzz-headers Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gofuzzheaders

import (
	"fmt"
	"reflect"
)

type Continue struct {
	F *ConsumeFuzzer
}

// Fuzz continues fuzzing obj. obj must be a pointer.
// This is compatible with gofuzz's Continue.Fuzz method.
func (c Continue) Fuzz(obj interface{}) {
	v := reflect.ValueOf(obj)
	if v.Kind() != reflect.Ptr {
		panic("Fuzz: obj must be a pointer")
	}
	c.F.populateValue(v.Elem(), 0, true)
}

// FuzzNoCustom continues fuzzing obj without calling custom fuzz functions.
// This is compatible with gofuzz's Continue.FuzzNoCustom method.
func (c Continue) FuzzNoCustom(obj interface{}) {
	v := reflect.ValueOf(obj)
	if v.Kind() != reflect.Ptr {
		panic("FuzzNoCustom: obj must be a pointer")
	}
	c.F.populateValue(v.Elem(), 0, false)
}

func (f *ConsumeFuzzer) AddFuncs(fuzzFuncs []interface{}) {
	for i := range fuzzFuncs {
		v := reflect.ValueOf(fuzzFuncs[i])
		if v.Kind() != reflect.Func {
			panic("Need only funcs!")
		}
		t := v.Type()
		
		// Support both signatures:
		// 1. gofuzz-style: func(*T, Continue) (no return)
		// 2. go-fuzz-headers-style: func(*T, Continue) error
		validSignature := false
		if t.NumIn() == 2 {
			if t.NumOut() == 0 {
				// gofuzz-style: no return value
				validSignature = true
			} else if t.NumOut() == 1 {
				// go-fuzz-headers-style: returns error
				validSignature = true
			}
		}
		
		if !validSignature {
			fmt.Println("NumIn:", t.NumIn(), "NumOut:", t.NumOut())
			panic("fuzzFunc must have signature: func(*T, Continue) or func(*T, Continue) error")
		}
		
		argT := t.In(0)
		switch argT.Kind() {
		case reflect.Ptr, reflect.Map:
		default:
			panic("fuzzFunc must take pointer or map type")
		}
		if t.In(1) != reflect.TypeOf(Continue{}) {
			panic("fuzzFunc's second parameter must be type Continue")
		}
		f.Funcs[argT] = v
	}
}

func (f *ConsumeFuzzer) GenerateWithCustom(targetStruct interface{}) error {
	e := reflect.ValueOf(targetStruct).Elem()
	return f.fuzzStruct(e, true)
}

func (c Continue) GenerateStruct(targetStruct interface{}) error {
	return c.F.GenerateStruct(targetStruct)
}

func (c Continue) GenerateStructWithCustom(targetStruct interface{}) error {
	return c.F.GenerateWithCustom(targetStruct)
}

// Intn returns a random integer in [0, n). Compatible with gofuzz's Continue.Intn.
func (c Continue) Intn(n int) int {
	if n <= 0 {
		return 0
	}
	val, err := c.F.GetInt()
	if err != nil {
		return 0
	}
	if val < 0 {
		val = -val
	}
	return val % n
}

// RandBool returns a random boolean. Compatible with gofuzz's Continue.RandBool.
func (c Continue) RandBool() bool {
	val, err := c.F.GetBool()
	if err != nil {
		return false
	}
	return val
}

// RandString returns a random string. Compatible with gofuzz's Continue.RandString.
func (c Continue) RandString() string {
	val, err := c.F.GetString()
	if err != nil {
		return ""
	}
	return val
}

// Int31 returns a random int32. Compatible with gofuzz's Continue.Int31.
func (c Continue) Int31() int32 {
	val, err := c.F.GetInt()
	if err != nil {
		return 0
	}
	return int32(val)
}

// Int63 returns a random int64. Compatible with gofuzz's Continue.Int63.
func (c Continue) Int63() int64 {
	val, err := c.F.GetInt()
	if err != nil {
		return 0
	}
	return int64(val)
}

// Uint32 returns a random uint32. Compatible with gofuzz's Continue.Uint32.
func (c Continue) Uint32() uint32 {
	val, err := c.F.GetInt()
	if err != nil {
		return 0
	}
	if val < 0 {
		val = -val
	}
	return uint32(val)
}

// Int returns a random int. Compatible with gofuzz's Continue.Int.
func (c Continue) Int() int {
	val, err := c.F.GetInt()
	if err != nil {
		return 0
	}
	return val
}
