package gofuzzheaders

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

//
// ---------- Deterministic “expected” helpers ----------
//

func wantInt() int {
	const val = 0x1122334455667788
	return int(int64(val))
}

func wantString() string { return "abcdefghij" }

func wantBytes10() []byte {
	return []byte{3, 20, 37, 54, 71, 88, 105, 122, 139, 156}
}

//
// ---------- Debug helpers ----------
//

func hexDump(b []byte, headTail int) string {
	if len(b) == 0 {
		return "<empty>"
	}
	if headTail <= 0 || 2*headTail >= len(b) {
		return hex.EncodeToString(b)
	}
	head := hex.EncodeToString(b[:headTail])
	tail := hex.EncodeToString(b[len(b)-headTail:])
	return fmt.Sprintf("%s ... (%d bytes elided) ... %s", head, len(b)-2*headTail, tail)
}

func dumpStruct(v any) string {
	return fmt.Sprintf("%T %+v", v, v)
}

//
// ---------- Minimal local stand-ins for Istio referenced types ----------
//

type NodeType string

type LabelsCollection []map[string]string

type Hostname string

type Port struct {
	Name     string
	Port     int
	Protocol string
}
type PortList []Port

type Service struct {
	Hostname    Hostname
	Address     string
	ClusterVIPs map[string]string
	Ports       PortList
}
type ServiceInstance struct {
	Service *Service
}

type SidecarScope struct{}

type Locality struct {
	Region  string
	Zone    string
	SubZone string
}

type ProxyPushStatus struct{}

type AuthorizationPolicies struct{}
type Environment struct{}

//
// ---------- Local replicas of Istio structs (public fields only) ----------
//

type ProxyReplica struct {
	ClusterID        string
	Type             NodeType
	IPAddresses      []string
	ID               string
	Locality         *Locality
	DNSDomain        string
	ConfigNamespace  string
	TrustDomain      string
	Metadata         map[string]string
	SidecarScope     *SidecarScope
	ServiceInstances []*ServiceInstance
	WorkloadLabels   LabelsCollection
}

type PushContextReplica struct {
	ProxyStatus      map[string]map[string]ProxyPushStatus
	Start            time.Time
	End              time.Time
	AuthzPolicies    *AuthorizationPolicies
	Env              *Environment
	ServicePort2Name map[string]PortList           `json:"-"`
	ServiceAccounts  map[Hostname]map[int][]string `json:"-"`
}

//
// ---------- Additional local demo types used across tests ----------
//

type innerTD struct {
	N     int
	Label string
}

type demoTD struct {
	ID     int `json:",omitempty"`
	Name   string
	Data   []byte `json:",omitempty"`
	Tags   []string
	Nums   []int
	PValue *int
	Inners []innerTD
	Opt    *innerTD `json:",omitempty"`
}

type onlyPrimsTD struct {
	B bool
	I int
	U uint
	F float64
	S string
}

type nestedTD struct {
	A   demoTD
	B   innerTD
	Ptr *innerTD
}

type sliceOnlyTD struct {
	Words []string
	Nums  []int
	Raw   []byte `json:",omitempty"`
}

//
// ---------- The table-driven test ----------
//

func TestBuildSeedAndGenerateStruct_TableDriven_WithLocalIstioReplicas(t *testing.T) {
	// Use a strict, deep config so presence is always true, containers aren’t auto-optional,
	// and nested structures are fully traversed.
	cfg := DefaultConfig()
	cfg.ContainersOptional = false // only optional if `omitempty`
	cfg.OptionalPresentDenom = 1   // (b % 1) < 1 ⇒ always present
	cfg.OptionalPresentNum = 1
	cfg.MaxDepth = 16 // IMPORTANT: ensure nested Service fields are encoded/decoded

	pol := DefaultSeedPolicy() // strings=10, slices/maps=2, include+populate all

	tests := []struct {
		name   string
		typ    reflect.Type
		assert func(t *testing.T, v any)
	}{
		{
			name: "demoTD rich struct",
			typ:  reflect.TypeOf(demoTD{}),
			assert: func(t *testing.T, v any) {
				out := v.(*demoTD)

				if out.ID != wantInt() {
					t.Fatalf("ID mismatch: got %v want %v", out.ID, wantInt())
				}
				if out.Name != wantString() {
					t.Fatalf("Name mismatch: got %q want %q", out.Name, wantString())
				}
				if got := out.Data; !reflect.DeepEqual(got, wantBytes10()) {
					t.Fatalf("Data mismatch: got %#v want %#v", got, wantBytes10())
				}

				if len(out.Tags) != 2 {
					t.Fatalf("Tags len: got %d want 2", len(out.Tags))
				}
				for i, s := range out.Tags {
					if s != wantString() {
						t.Fatalf("Tags[%d]: got %q want %q", i, s, wantString())
					}
				}
				if len(out.Nums) != 2 {
					t.Fatalf("Nums len: got %d want 2", len(out.Nums))
				}
				for i, n := range out.Nums {
					if n != wantInt() {
						t.Fatalf("Nums[%d]: got %v want %v", i, n, wantInt())
					}
				}

				if out.PValue == nil {
					t.Fatalf("PValue is nil; want non-nil")
				}
				if *out.PValue != wantInt() {
					t.Fatalf("PValue: got %v want %v", *out.PValue, wantInt())
				}

				if len(out.Inners) != 2 {
					t.Fatalf("Inners len: got %d want 2", len(out.Inners))
				}
				for i, in := range out.Inners {
					if in.N != wantInt() {
						t.Fatalf("Inners[%d].N: got %v want %v", i, in.N, wantInt())
					}
					if in.Label != wantString() {
						t.Fatalf("Inners[%d].Label: got %q want %q", i, in.Label, wantString())
					}
				}

				if out.Opt == nil {
					t.Fatalf("Opt is nil; want non-nil")
				}
				if out.Opt.N != wantInt() {
					t.Fatalf("Opt.N: got %v want %v", out.Opt.N, wantInt())
				}
				if out.Opt.Label != wantString() {
					t.Fatalf("Opt.Label: got %q want %q", out.Opt.Label, wantString())
				}
			},
		},
		{
			name: "onlyPrimsTD primitives",
			typ:  reflect.TypeOf(onlyPrimsTD{}),
			assert: func(t *testing.T, v any) {
				out := v.(*onlyPrimsTD)
				if !out.B {
					t.Fatalf("B: got false want true")
				}
				if out.I != wantInt() {
					t.Fatalf("I: got %v want %v", out.I, wantInt())
				}
				if out.U == 0 {
					t.Fatalf("U: got 0 want non-zero")
				}
				if out.F == 0 {
					t.Fatalf("F: got 0 want non-zero finite")
				}
				if out.S != wantString() {
					t.Fatalf("S: got %q want %q", out.S, wantString())
				}
			},
		},
		{
			name: "nestedTD nested structs and pointer",
			typ:  reflect.TypeOf(nestedTD{}),
			assert: func(t *testing.T, v any) {
				out := v.(*nestedTD)

				if out.A.Name != wantString() {
					t.Fatalf("A.Name: got %q want %q", out.A.Name, wantString())
				}
				if out.A.ID != wantInt() {
					t.Fatalf("A.ID: got %v want %v", out.A.ID, wantInt())
				}
				if out.B.N != wantInt() {
					t.Fatalf("B.N: got %v want %v", out.B.N, wantInt())
				}
				if out.B.Label != wantString() {
					t.Fatalf("B.Label: got %q want %q", out.B.Label, wantString())
				}
				if out.Ptr == nil {
					t.Fatalf("Ptr is nil; want non-nil")
				}
				if out.Ptr.Label != wantString() {
					t.Fatalf("Ptr.Label: got %q want %q", out.Ptr.Label, wantString())
				}
			},
		},
		{
			name: "sliceOnlyTD slices and []byte",
			typ:  reflect.TypeOf(sliceOnlyTD{}),
			assert: func(t *testing.T, v any) {
				out := v.(*sliceOnlyTD)

				if len(out.Words) != 2 {
					t.Fatalf("Words len: got %d want 2", len(out.Words))
				}
				for i, s := range out.Words {
					if s != wantString() {
						t.Fatalf("Words[%d]: got %q want %q", i, s, wantString())
					}
				}

				if len(out.Nums) != 2 {
					t.Fatalf("Nums len: got %d want 2", len(out.Nums))
				}
				for i, n := range out.Nums {
					if n != wantInt() {
						t.Fatalf("Nums[%d]: got %v want %v", i, n, wantInt())
					}
				}

				if got := out.Raw; !reflect.DeepEqual(got, wantBytes10()) {
					t.Fatalf("Raw []byte mismatch: got %#v want %#v", got, wantBytes10())
				}
			},
		},

		// ---------- Local replicas of Istio types ----------

		{
			name: "ProxyReplica (Istio Proxy shape) — exact assertions on all fields",
			typ:  reflect.TypeOf(ProxyReplica{}),
			assert: func(t *testing.T, v any) {
				out := v.(*ProxyReplica)

				t.Logf("[DEBUG] ProxyReplica seed->struct: %+v", *out)

				// Scalars
				if out.ClusterID != wantString() {
					t.Fatalf("ClusterID: got %q want %q", out.ClusterID, wantString())
				}
				if string(out.Type) != wantString() {
					t.Fatalf("Type: got %q want %q", out.Type, wantString())
				}
				if out.ID != wantString() {
					t.Fatalf("ID: got %q want %q", out.ID, wantString())
				}
				if out.DNSDomain != wantString() {
					t.Fatalf("DNSDomain: got %q want %q", out.DNSDomain, wantString())
				}
				if out.ConfigNamespace != wantString() {
					t.Fatalf("ConfigNamespace: got %q want %q", out.ConfigNamespace, wantString())
				}
				if out.TrustDomain != wantString() {
					t.Fatalf("TrustDomain: got %q want %q", out.TrustDomain, wantString())
				}

				// IPs
				if len(out.IPAddresses) != 2 {
					t.Fatalf("IPAddresses len: got %d want 2", len(out.IPAddresses))
				}
				for i, ip := range out.IPAddresses {
					if ip != wantString() {
						t.Fatalf("IPAddresses[%d]: got %q want %q", i, ip, wantString())
					}
				}

				// Locality
				if out.Locality == nil {
					t.Fatalf("Locality is nil; want non-nil")
				}
				if out.Locality.Region != wantString() {
					t.Fatalf("Locality.Region: got %q want %q", out.Locality.Region, wantString())
				}
				if out.Locality.Zone != wantString() {
					t.Fatalf("Locality.Zone: got %q want %q", out.Locality.Zone, wantString())
				}
				if out.Locality.SubZone != wantString() {
					t.Fatalf("Locality.SubZone: got %q want %q", out.Locality.SubZone, wantString())
				}

				// Metadata map (duplicate keys collapse to one entry)
				if out.Metadata == nil {
					t.Fatalf("Metadata is nil")
				}
				if len(out.Metadata) != 1 {
					t.Fatalf("Metadata len: got %d want 1", len(out.Metadata))
				}
				if val, ok := out.Metadata[wantString()]; !ok || val != wantString() {
					t.Fatalf("Metadata: want [%q:%q], got %v", wantString(), wantString(), out.Metadata)
				}

				// SidecarScope pointer
				if out.SidecarScope == nil {
					t.Fatalf("SidecarScope is nil")
				}

				// ServiceInstances
				if out.ServiceInstances == nil {
					t.Fatalf("ServiceInstances nil")
				}
				if len(out.ServiceInstances) != 2 {
					t.Fatalf("ServiceInstances len: got %d want 2", len(out.ServiceInstances))
				}
				for i, si := range out.ServiceInstances {
					if si == nil {
						t.Fatalf("ServiceInstances[%d] is nil", i)
					}
					if si.Service == nil {
						t.Fatalf("ServiceInstances[%d].Service is nil", i)
					}
					svc := si.Service
					if string(svc.Hostname) != wantString() {
						t.Fatalf("Service[%d].Hostname: got %q want %q", i, string(svc.Hostname), wantString())
					}
					if svc.Address != wantString() {
						t.Fatalf("Service[%d].Address: got %q want %q", i, svc.Address, wantString())
					}

					// ClusterVIPs (expect 1 due to duplicate key)
					if svc.ClusterVIPs == nil {
						t.Fatalf("Service[%d].ClusterVIPs is nil", i)
					}
					if len(svc.ClusterVIPs) != 1 {
						t.Fatalf("Service[%d].ClusterVIPs len: got %d want 1", i, len(svc.ClusterVIPs))
					}
					if val, ok := svc.ClusterVIPs[wantString()]; !ok || val != wantString() {
						t.Fatalf("Service[%d].ClusterVIPs: want [%q:%q], got %v", i, wantString(), wantString(), svc.ClusterVIPs)
					}

					// Ports slice
					if len(svc.Ports) != 2 {
						t.Fatalf("Service[%d].Ports len: got %d want 2", i, len(svc.Ports))
					}
					for j, p := range svc.Ports {
						if p.Name != wantString() {
							t.Fatalf("Service[%d].Ports[%d].Name: got %q want %q", i, j, p.Name, wantString())
						}
						if p.Port != wantInt() {
							t.Fatalf("Service[%d].Ports[%d].Port: got %v want %v", i, j, p.Port, wantInt())
						}
						if p.Protocol != wantString() {
							t.Fatalf("Service[%d].Ports[%d].Protocol: got %q want %q", i, j, p.Protocol, wantString())
						}
					}
				}

				// WorkloadLabels (slice of maps) — duplicate keys collapse to 1
				if len(out.WorkloadLabels) != 2 {
					t.Fatalf("WorkloadLabels len: got %d want 2", len(out.WorkloadLabels))
				}
				for i, m := range out.WorkloadLabels {
					if m == nil {
						t.Fatalf("WorkloadLabels[%d] is nil map", i)
					}
					if len(m) != 1 {
						t.Fatalf("WorkloadLabels[%d] len: got %d want 1", i, len(m))
					}
					if val, ok := m[wantString()]; !ok || val != wantString() {
						t.Fatalf("WorkloadLabels[%d]: want [%q:%q], got %v", i, wantString(), wantString(), m)
					}
				}
			},
		},
		{
			name: "PushContextReplica (Istio PushContext shape)",
			typ:  reflect.TypeOf(PushContextReplica{}),
			assert: func(t *testing.T, v any) {
				out := v.(*PushContextReplica)

				if out.ProxyStatus == nil || len(out.ProxyStatus) == 0 {
					t.Fatalf("ProxyStatus: expected non-nil with entries")
				}
				// time.Time remain zero
				if !out.Start.IsZero() || !out.End.IsZero() {
					t.Fatalf("Start/End: expected zero values")
				}
				if out.AuthzPolicies == nil {
					t.Fatalf("AuthzPolicies: expected non-nil")
				}
				if out.Env == nil {
					t.Fatalf("Env: expected non-nil")
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			EnableSeedDebug(true)
			seed, err := BuildSeedForTypes(cfg, pol, tc.typ)
			if err != nil {
				t.Fatalf("BuildSeedForTypes failed: %v", err)
			}
			t.Logf("[DEBUG] type=%s seedLen=%d seed(head/tail): %s", tc.typ, len(seed), hexDump(seed, 32))

			cf := NewConsumerWithConfig(seed, cfg)

			// construct zero value of the type and pass a pointer
			val := reflect.New(tc.typ).Interface()
			if err := cf.GenerateStruct(val); err != nil {
				t.Fatalf("GenerateStruct failed: %v", err)
			}
			t.Logf("[SEED TRACE]\n%s", SeedTrace())
			t.Logf("[DEBUG] populated: %s", dumpStruct(reflect.Indirect(reflect.ValueOf(val)).Interface()))

			tc.assert(t, val)
		})
	}
}

func TestPointerToIntAlignment(t *testing.T) {
	cfg := DefaultConfig()
	// deterministic & deep enough
	cfg.ContainersOptional = false
	cfg.OptionalPresentDenom = 1
	cfg.OptionalPresentNum = 1
	cfg.MaxDepth = 8

	pol := DefaultSeedPolicy()

	EnableSeedDebug(true)
	defer EnableSeedDebug(false)

	typ := reflect.TypeOf(ptrIntCase{})
	seed, err := BuildSeedForTypes(cfg, pol, typ)
	if err != nil {
		t.Fatalf("BuildSeedForTypes failed: %v", err)
	}
	t.Logf("[SEED TRACE]\n%s", SeedTrace())

	var out ptrIntCase
	cf := NewConsumer(seed)
	if err := cf.GenerateStruct(&out); err != nil {
		t.Fatalf("GenerateStruct failed: %v", err)
	}

	if out.P == nil {
		t.Fatalf("P is nil; expected allocated *int")
	}
	want := int(0x1122334455667788)
	if *out.P != want {
		t.Fatalf("P: got %d (0x%x) want %d (0x%x)", *out.P, *out.P, want, want)
	}
	if out.After != "abcdefghij" {
		t.Fatalf("After: got %q want %q", out.After, "abcdefghij")
	}
}

// The shape under test.
type ptrIntCase struct {
	P     *int
	After string
}

// Handy function if you prefer to reference the type via a function in tests.
func ptrIntCaseType() reflect.Type {
	return reflect.TypeOf(ptrIntCase{})
}

// Optional constructor, if you want a zero-value instance.
func newPtrIntCase() ptrIntCase {
	return ptrIntCase{}
}

func TestGetInt_TopLevel_Int_and_PtrInt(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxDepth = 8

	pol := DefaultSeedPolicy()

	const want = int(0x1122334455667788)

	// ---- plain int ----
	seedInt, err := BuildSeedForTypes(cfg, pol, reflect.TypeOf(int(0)))
	if err != nil {
		t.Fatalf("BuildSeedForTypes(int) failed: %v", err)
	}
	cfInt := NewConsumer(seedInt)
	gotInt, err := cfInt.GetInt()
	if err != nil {
		t.Fatalf("GetInt (plain) failed: %v", err)
	}
	if gotInt != want {
		t.Fatalf("plain int: got %d (0x%x) want %d (0x%x)", gotInt, gotInt, want, want)
	}

	// ---- *int (strip pointer control bytes) ----
	ptrT := reflect.TypeOf((*int)(nil))
	seedPtr, err := BuildSeedForTypes(cfg, pol, ptrT)
	if err != nil {
		t.Fatalf("BuildSeedForTypes(*int) failed: %v", err)
	}
	// Seed layout (from our seed builder): [alloc=0x01] [pointee-gate=0x01] [pointee-populate=0x01] [8-byte int LE]
	// Detect and strip up to the first 3 leading 0x01 control bytes to position at the int payload.
	lead := 0
	for lead < len(seedPtr) && lead < 3 && seedPtr[lead] == 0x01 {
		lead++
	}
	if lead == 0 {
		t.Fatalf("expected leading control bytes before pointee payload; seed head=%s", hex.EncodeToString(seedPtr[:min(8, len(seedPtr))]))
	}
	payload := seedPtr[lead:]
	if len(payload) < 8 {
		t.Fatalf("not enough bytes for int payload after stripping %d control bytes (len=%d)", lead, len(payload))
	}

	cfPtr := NewConsumer(payload)
	gotPtr, err := cfPtr.GetInt()
	if err != nil {
		t.Fatalf("GetInt (pointee) failed: %v", err)
	}
	if gotPtr != want {
		t.Fatalf("*int pointee: got %d (0x%x) want %d (0x%x); stripped=%d head=%s",
			gotPtr, gotPtr, want, want, lead, hex.EncodeToString(seedPtr[:min(12, len(seedPtr))]))
	}
}

func TestPointerToIntAlignment_GenerateStruct(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ContainersOptional = false
	cfg.OptionalPresentDenom = 1
	cfg.OptionalPresentNum = 1
	cfg.MaxDepth = 8

	pol := DefaultSeedPolicy()

	EnableSeedDebug(true)
	defer EnableSeedDebug(false)

	typ := reflect.TypeOf(ptrIntCase{})
	seed, err := BuildSeedForTypes(cfg, pol, typ)
	if err != nil {
		t.Fatalf("BuildSeedForTypes failed: %v", err)
	}
	t.Logf("[SEED TRACE]\n%s", SeedTrace())

	var out ptrIntCase
	cf := NewConsumer(seed)
	if err := cf.GenerateStruct(&out); err != nil {
		t.Fatalf("GenerateStruct failed: %v", err)
	}

	if out.P == nil {
		t.Fatalf("P is nil; expected allocated *int")
	}
	want := int(0x1122334455667788)
	if *out.P != want {
		t.Fatalf("P: got %d (0x%x) want %d (0x%x)", *out.P, *out.P, want, want)
	}
	if out.After != "abcdefghij" {
		t.Fatalf("After: got %q want %q", out.After, "abcdefghij")
	}
}

type ptrStructOptCase struct {
	Opt *innerTD `json:",omitempty"`
	S   string
}

func TestPointerToStructOptional_GenerateStruct(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ContainersOptional = false
	cfg.OptionalPresentDenom = 1
	cfg.OptionalPresentNum = 1
	cfg.MaxDepth = 8

	pol := DefaultSeedPolicy()

	EnableSeedDebug(true)
	defer EnableSeedDebug(false)

	typ := reflect.TypeOf(ptrStructOptCase{})
	seed, err := BuildSeedForTypes(cfg, pol, typ)
	if err != nil {
		t.Fatalf("BuildSeedForTypes failed: %v", err)
	}
	t.Logf("[SEED TRACE]\n%s", SeedTrace())

	var out ptrStructOptCase
	cf := NewConsumer(seed)
	if err := cf.GenerateStruct(&out); err != nil {
		t.Fatalf("GenerateStruct failed: %v", err)
	}

	if out.Opt == nil {
		t.Fatalf("Opt is nil; expected allocated *innerTD")
	}
	wantN := int(0x1122334455667788)
	if out.Opt.N != wantN {
		t.Fatalf("Opt.N: got %d (0x%x) want %d (0x%x)", out.Opt.N, out.Opt.N, wantN, wantN)
	}
	if out.Opt.Label != "abcdefghij" {
		t.Fatalf("Opt.Label: got %q want %q", out.Opt.Label, "abcdefghij")
	}
	if out.S != "abcdefghij" {
		t.Fatalf("S: got %q want %q", out.S, "abcdefghij")
	}
}

type demoTagsOnly struct {
	Tags []string
	Tail string
}

func TestSliceOfStrings_LengthAndValues(t *testing.T) {
	cfg := DefaultConfig()
	cfg.ContainersOptional = false
	cfg.OptionalPresentDenom, cfg.OptionalPresentNum = 1, 1
	cfg.MaxDepth = 6
	pol := DefaultSeedPolicy()

	EnableSeedDebug(true)
	defer EnableSeedDebug(false)

	typ := reflect.TypeOf(demoTagsOnly{})
	seed, err := BuildSeedForTypes(cfg, pol, typ)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("[SEED TRACE]\n%s", SeedTrace())

	var out demoTagsOnly
	cf := NewConsumer(seed)
	if err := cf.GenerateStruct(&out); err != nil {
		t.Fatal(err)
	}

	if got := len(out.Tags); got != 2 {
		t.Fatalf("Tags len: got %d want 2", got)
	}
	for i := 0; i < 2; i++ {
		if out.Tags[i] != "abcdefghij" {
			t.Fatalf("Tags[%d]: got %q want %q", i, out.Tags[i], "abcdefghij")
		}
	}
	if out.Tail != "abcdefghij" {
		t.Fatalf("Tail: got %q want %q", out.Tail, "abcdefghij")
	}
}

// innerSeedless is a small nested struct used to test recursive allocation
// behavior when no seed data (bytes) are available. It includes a mix of
// scalar, slice, and pointer fields.
type innerSeedless struct {
	A int
	B []string
	C *int
}

// outerSeedless combines several container and scalar fields, including a
// nested struct (St) and a pointer to a nested struct (P). This type is
// designed to cover all allocation cases: pointers, maps, slices, arrays,
// scalars, and nested structs.
type outerSeedless struct {
	P   *innerSeedless // pointer to struct
	M   map[string]int // map container
	S   []uint32       // slice container
	Arr [3]byte        // fixed-size array
	I   int            // scalar
	St  innerSeedless  // nested struct
}

// -----------------------------------------------------------------------------
// TestGenerateStruct_NoSeeds_AllocatesMandatoryFields_NoPopulate
// -----------------------------------------------------------------------------
//
// This test verifies the *allocation-only* behavior of GenerateStruct when
// there are *no seed bytes* available (i.e., insufficient seeds).
//
// Expected behavior:
//   - GenerateStruct MUST return nil (no errors ever).
//   - All "mandatory" containers (pointers, maps, slices, nested structs)
//     should be created and non-nil.
//   - Slices should always have length 1 and contain zero-value elements.
//   - Maps should be allocated but empty.
//   - Scalars and array elements should remain zero-values (unpopulated).
//
// This ensures that even without bytes left, the consumer still builds a full
// structural "skeleton" of the target type.
func TestGenerateStruct_NoSeeds_AllocatesMandatoryFields_NoPopulate(t *testing.T) {
	// Input: completely empty byte slice => "no seeds"
	data := []byte{}

	// Use default config but ensure containers are *not optional*,
	// so all containers are treated as mandatory and should appear.
	cfg := DefaultConfig()
	cfg.ContainersOptional = false

	c := NewConsumerWithConfig(data, cfg)

	var out outerSeedless
	if err := c.GenerateStruct(&out); err != nil {
		t.Fatalf("GenerateStruct returned an error; expected nil: %v", err)
	}

	// --- Pointer / Map / Nested struct allocation checks ---

	// Pointer to struct should be allocated and non-nil.
	if out.P == nil {
		t.Fatalf("expected out.P (pointer to struct) to be non-nil")
	}
	// Map should be allocated and non-nil.
	if out.M == nil {
		t.Fatalf("expected out.M (map) to be non-nil")
	}
	// Nested struct’s slice and pointer fields should also be allocated.
	if out.St.B == nil {
		t.Fatalf("expected out.St.B (slice in nested struct) to be non-nil")
	}
	if out.St.C == nil {
		t.Fatalf("expected out.St.C (pointer in nested struct) to be non-nil")
	}

	// --- Slice allocation checks ---

	// Top-level slice should be created with len=1.
	if out.S == nil || len(out.S) != 1 {
		t.Fatalf("expected out.S (slice) to be length 1; got len=%d", len(out.S))
	}
	// Its element should be zero-value (unpopulated).
	if out.S[0] != 0 {
		t.Fatalf("expected out.S[0] to be zero-value; got %v", out.S[0])
	}

	// Nested struct’s slice should also be len=1 with empty element.
	if out.St.B == nil || len(out.St.B) != 1 {
		t.Fatalf("expected out.St.B (slice) to be length 1; got len=%d", len(out.St.B))
	}
	if out.St.B[0] != "" {
		t.Fatalf("expected out.St.B[0] to be zero-value string; got %q", out.St.B[0])
	}

	// --- Map population check ---

	// Maps should be allocated but empty (no data populated).
	if len(out.M) != 0 {
		t.Fatalf("expected out.M to be empty; got len=%d", len(out.M))
	}

	// --- Scalar checks ---

	// All scalar fields should remain zero-value.
	if out.I != 0 {
		t.Fatalf("expected out.I (int) to remain zero; got %d", out.I)
	}
	if out.P.A != 0 || out.St.A != 0 {
		t.Fatalf("expected nested scalar fields to remain zero; got P.A=%d St.A=%d", out.P.A, out.St.A)
	}
	// Arrays should remain entirely zeroed.
	if out.Arr != ([3]byte{}) {
		t.Fatalf("expected out.Arr (array) to remain all-zero; got %v", out.Arr)
	}

	// --- Nested pointer content check ---

	// Pointer-to-int should be allocated but still hold the zero-value.
	if out.St.C == nil {
		t.Fatalf("expected out.St.C to be allocated (non-nil)")
	}
	if *out.St.C != 0 {
		t.Fatalf("expected *out.St.C to be zero; got %d", *out.St.C)
	}
}

// -----------------------------------------------------------------------------
// TestGenerateStruct_AlwaysReturnsNil_WithZeroSeeds
// -----------------------------------------------------------------------------
//
// This test verifies that GenerateStruct *never returns an error*, even when
// invoked with nil or zero-length input. This enforces the new contract that
// "insufficient seeds" is not a failure case.
func TestGenerateStruct_AlwaysReturnsNil_WithZeroSeeds(t *testing.T) {
	c := NewConsumer([]byte{})
	var out outerSeedless
	if err := c.GenerateStruct(&out); err != nil {
		t.Fatalf("expected nil error; got %v", err)
	}
}

// -----------------------------------------------------------------------------
// TestGenerateStruct_SliceLengthOneAndZeroValues
// -----------------------------------------------------------------------------
//
// This test isolates slice handling to confirm that every slice field is
// created with exactly one element and that all elements are zero-valued.
//
// Expected behavior:
//   - Each slice should be allocated (non-nil).
//   - Each slice should have len=1.
//   - The single element should be zero-value for its type.
func TestGenerateStruct_SliceLengthOneAndZeroValues(t *testing.T) {
	// Disable container-optional behavior to guarantee presence of slices.
	cfg := DefaultConfig()
	cfg.ContainersOptional = false

	// Using nil == no seeds triggers the allocation-only behavior.
	c := NewConsumerWithConfig(nil, cfg)

	type sliceHolder struct {
		Ints    []int
		Strings []string
		Bytes   []byte
	}

	var sh sliceHolder
	if err := c.GenerateStruct(&sh); err != nil {
		t.Fatalf("GenerateStruct returned error; expected nil: %v", err)
	}

	// Int slice: should exist, len=1, and contain zero.
	if sh.Ints == nil || len(sh.Ints) != 1 || sh.Ints[0] != 0 {
		t.Fatalf("expected Ints slice len=1 with zero element; got len=%d val=%v", len(sh.Ints), sh.Ints)
	}

	// String slice: should exist, len=1, and contain empty string.
	if sh.Strings == nil || len(sh.Strings) != 1 || sh.Strings[0] != "" {
		t.Fatalf("expected Strings slice len=1 with empty string; got len=%d val=%v", len(sh.Strings), sh.Strings)
	}

	// Byte slice: should exist, len=1, and contain a single zero byte.
	if sh.Bytes == nil || len(sh.Bytes) != 1 || sh.Bytes[0] != 0x00 {
		t.Fatalf("expected Bytes slice len=1 with 0x00; got len=%d val=%v", len(sh.Bytes), sh.Bytes)
	}
}

/*
   ----------------------------------------------------------------------------
   Minimal Istio-style fuzz scaffolding used by these tests
   ----------------------------------------------------------------------------

   Helper wraps a testing.T and a ConsumeFuzzer (cf). It mimics the shape used
   by Istio's fuzz utilities, where a "Helper" is handed around and used by
   generic helpers like fuzz.Struct[T](fg, validators...).

   We purposely configure the consumer with ContainersOptional=false so that
   container fields (maps/slices/pointers) are treated as mandatory and created
   even when there are insufficient seeds, which matches the behavior that
   Istio relies on when fuzzing its structs.
*/

type Helper struct {
	t  *testing.T
	cf *ConsumeFuzzer
}

func New(t *testing.T, seed []byte) Helper {
	cfg := DefaultConfig()
	cfg.ContainersOptional = false
	return Helper{t: t, cf: NewConsumerWithConfig(seed, cfg)}
}

func Struct[T any](h Helper, validators ...func(T) bool) T {
	d := new(T)
	if err := h.cf.GenerateStruct(d); err != nil {
		h.t.Skip(err.Error())
	}
	for _, v := range validators {
		if !v(*d) {
			h.t.Skip("validator rejected generated value")
		}
	}
	return *d
}

func runFuzzShim(t *testing.T, seed []byte, ff func(fg Helper)) {
	BaseCases(t)
	defer Finalize()
	fg := New(t, seed)
	ff(fg)
}

func BaseCases(t *testing.T) {}
func Finalize()              {}

// --- Types used in the test (unique names to avoid collisions) ---

// Bundle-like type
type istioBundle struct {
	TrustDomain string
	Aliases     []string
}

// PushContext-like type
type istioPushContext struct {
	MeshID   string
	Features map[string]bool
	Gateways []string
}

// Stand-ins referenced by the Proxy copy
type istioNodeType int

const (
	istioNodeSidecar istioNodeType = iota
	istioNodeRouter
	istioNodeWaypoint
)

type istioLocality struct {
	Region, Zone, Subzone string
}
type istioNodeMetadata struct {
	Namespace string
	Labels    map[string]string
}
type istioSidecarScope struct {
	Name      string
	Workloads []string
}
type istioMergedGateway struct{ Servers []string }
type istioPrevMergedGateway struct{ Revision int }
type istioServiceTarget struct {
	Name string
	Port int
}
type istioVersion struct{ Major, Minor, Patch int }
type istioIdentity struct{ SPIFFE string }
type istioXdsResourceGenerator interface{ Generate() error }
type istioWatchedResource struct {
	TypeURL string
	Name    string
}
type istioNode struct {
	ID       string
	Cluster  string
	Metadata map[string]any
}
type istioPushCtx struct {
	Version   string
	ClusterID string
	Services  map[string][]int
}

// Proxy copy (includes an Address []byte field as your earlier assertions expect)
type proxyCopy struct {
	sync.RWMutex

	Type            istioNodeType
	IPAddresses     []string
	ID              string
	Locality        *istioLocality
	DNSDomain       string
	ConfigNamespace string
	Labels          map[string]string
	Metadata        *istioNodeMetadata

	SidecarScope     *istioSidecarScope
	PrevSidecarScope *istioSidecarScope

	MergedGateway     *istioMergedGateway
	PrevMergedGateway *istioPrevMergedGateway

	ServiceTargets []istioServiceTarget

	IstioVersion     *istioVersion
	VerifiedIdentity *istioIdentity

	GlobalUnicastIP string

	XdsResourceGenerator istioXdsResourceGenerator
	WatchedResources     map[string]*istioWatchedResource

	XdsNode         *istioNode
	LastPushContext *istioPushCtx
	LastPushTime    time.Time

	// Byte slice we can assert on deterministically (length > 0 with seed)
	Address []byte
}

// Optional validator for PushContext-like
func validateIstioPush(pc *istioPushContext) bool {
	return pc != nil && pc.Features != nil && pc.Gateways != nil && len(pc.Gateways) > 0
}

// Optional validator for Proxy copy
func validateProxyCopy(p *proxyCopy) bool {
	return p != nil &&
		p.IPAddresses != nil &&
		p.Labels != nil &&
		p.WatchedResources != nil &&
		p.Locality != nil &&
		p.Metadata != nil &&
		p.SidecarScope != nil &&
		p.PrevSidecarScope != nil &&
		p.MergedGateway != nil &&
		p.PrevMergedGateway != nil &&
		p.IstioVersion != nil &&
		p.VerifiedIdentity != nil &&
		p.XdsNode != nil &&
		p.LastPushContext != nil
}

type proxyCopySeedable struct {
	sync.RWMutex

	Type            istioNodeType
	IPAddresses     []string
	ID              string
	Locality        *istioLocality
	DNSDomain       string
	ConfigNamespace string
	Labels          map[string]string
	Metadata        *istioNodeMetadata

	SidecarScope     *istioSidecarScope
	PrevSidecarScope *istioSidecarScope

	MergedGateway     *istioMergedGateway
	PrevMergedGateway *istioPrevMergedGateway

	ServiceTargets []istioServiceTarget

	IstioVersion     *istioVersion
	VerifiedIdentity *istioIdentity

	GlobalUnicastIP string

	// XdsResourceGenerator intentionally omitted (interface cannot be seeded)
	WatchedResources map[string]*istioWatchedResource

	XdsNode         *istioNode
	LastPushContext *istioPushCtx
	LastPushTime    time.Time
	Address         []byte
}

// assertAllStringsEqual walks v and ensures every string field/elem/key/value equals `want`.
func assertAllStringsEqual(t *testing.T, name string, v any, want string) {
	t.Helper()
	var mismatches []string
	seen := map[uintptr]bool{}

	var visit func(path string, rv reflect.Value)
	visit = func(path string, rv reflect.Value) {
		if !rv.IsValid() {
			return
		}
		// Unwrap interface
		if rv.Kind() == reflect.Interface && !rv.IsNil() {
			rv = rv.Elem()
		}
		switch rv.Kind() {
		case reflect.String:
			if rv.String() != want {
				mismatches = append(mismatches, fmt.Sprintf("%s = %q", path, rv.String()))
			}
		case reflect.Ptr:
			if rv.IsNil() {
				return
			}
			ptr := rv.Pointer()
			if ptr != 0 && seen[ptr] {
				return
			}
			if ptr != 0 {
				seen[ptr] = true
			}
			visit(path, rv.Elem())
		case reflect.Struct:
			// Treat time.Time as atomic
			if rv.Type().PkgPath() == "time" && rv.Type().Name() == "Time" {
				return
			}
			for i := 0; i < rv.NumField(); i++ {
				sf := rv.Type().Field(i)
				// Skip unexported fields
				if sf.PkgPath != "" {
					continue
				}
				visit(path+"."+sf.Name, rv.Field(i))
			}
		case reflect.Slice, reflect.Array:
			// Skip []byte; not strings.
			if rv.Type().Elem().Kind() == reflect.Uint8 {
				return
			}
			for i := 0; i < rv.Len(); i++ {
				visit(fmt.Sprintf("%s[%d]", path, i), rv.Index(i))
			}
		case reflect.Map:
			iter := rv.MapRange()
			for iter.Next() {
				k := iter.Key()
				val := iter.Value()
				// Check string keys/values directly, then recurse for nested content.
				if k.Kind() == reflect.String {
					if k.String() != want {
						mismatches = append(mismatches, fmt.Sprintf("%s[<key>] = %q", path, k.String()))
					}
				} else {
					visit(path+"[key]", k)
				}
				if val.Kind() == reflect.String {
					if val.String() != want {
						mismatches = append(mismatches, fmt.Sprintf("%s[<value>] = %q", path, val.String()))
					}
				} else {
					visit(path+"[value]", val)
				}
			}
		default:
			return
		}
	}

	visit(name, reflect.ValueOf(v))
	if len(mismatches) > 0 {
		t.Fatalf("%s: strings not equal to %q:\n  %s", name, want, strings.Join(mismatches, "\n  "))
	}
}

func TestIstioStyleWrapper_WithDeterministicSeed(t *testing.T) {
	cfg := DefaultConfig()
	pol := DefaultSeedPolicy()

	// Build a seed for the exact types we will generate, in this order:
	//   1) istioBundle (non-pointer)
	//   2) *istioPushContext (pointer)
	//   3) *proxyCopySeedable (pointer; same as proxyCopy but WITHOUT interface field)
	seed, err := BuildSeedForTypes(
		cfg, pol,
		reflect.TypeOf(istioBundle{}),
		reflect.TypeOf((*istioPushContext)(nil)),
		reflect.TypeOf((*proxyCopySeedable)(nil)),
	)
	if err != nil {
		t.Fatalf("BuildSeedForTypes failed: %v", err)
	}

	runFuzzShim(t, seed, func(fg Helper) {
		want := "abcdefghij"

		// 1) bundle := fuzz.Struct[trustdomain.Bundle](fg)
		bundle := Struct[istioBundle](fg)
		// Basic sanity (non-empty due to seed)
		if bundle.TrustDomain == "" {
			t.Fatalf("bundle.TrustDomain empty; want non-empty from seed")
		}
		if bundle.Aliases == nil || len(bundle.Aliases) == 0 {
			t.Fatalf("bundle.Aliases not allocated or empty; want non-empty from seed")
		}
		// All strings exactly "abcdefghij"
		assertAllStringsEqual(t, "bundle", bundle, want)

		// 2) push := fuzz.Struct[*model.PushContext](fg, validatePush)
		push := Struct[*istioPushContext](fg, validateIstioPush)
		if push == nil {
			t.Fatalf("push is nil; want non-nil")
		}
		// All strings exactly "abcdefghij"
		assertAllStringsEqual(t, "push", push, want)

		// 3) node := fuzz.Struct[*model.Proxy](fg)
		node := Struct[*proxyCopy](fg, validateProxyCopy)
		if node == nil {
			t.Fatalf("node is nil; want non-nil")
		}
		// All strings exactly "abcdefghij"
		assertAllStringsEqual(t, "node", node, want)

		// Optional: keep a few non-string sanity checks for structure
		if node.IPAddresses == nil || len(node.IPAddresses) == 0 {
			t.Fatalf("node.IPAddresses not allocated or empty; want non-empty from seed")
		}
		if node.Address == nil || len(node.Address) == 0 {
			t.Fatalf("node.Address not allocated or empty; want non-empty from seed")
		}
		if node.Labels == nil || node.WatchedResources == nil {
			t.Fatalf("node maps not allocated; want allocated from seed")
		}
	})
}

func TestIstioStyleWrapper_ProxyCopy_InsufficientSeeds(t *testing.T) {
	seed := []byte{} // triggers insufficient-seeds (allocate-only) path

	runFuzzShim(t, seed, func(fg Helper) {
		node := Struct[*proxyCopy](fg, validateProxyCopy)
		if node == nil {
			t.Fatalf("expected *proxyCopy to be non-nil")
		}

		// Scalars remain zero
		if node.ID != "" {
			t.Fatalf("expected ID to be empty, got %q", node.ID)
		}
		if node.DNSDomain != "" {
			t.Fatalf("expected DNSDomain to be empty, got %q", node.DNSDomain)
		}
		if node.ConfigNamespace != "" {
			t.Fatalf("expected ConfigNamespace to be empty, got %q", node.ConfigNamespace)
		}
		if node.GlobalUnicastIP != "" {
			t.Fatalf("expected GlobalUnicastIP to be empty, got %q", node.GlobalUnicastIP)
		}
		if !node.LastPushTime.IsZero() {
			t.Fatalf("expected LastPushTime to be zero, got %v", node.LastPushTime)
		}

		// Slices: len==1, zero-value element
		if node.IPAddresses == nil || len(node.IPAddresses) != 1 {
			t.Fatalf("expected IPAddresses len==1, got %d", len(node.IPAddresses))
		}
		if node.IPAddresses[0] != "" {
			t.Fatalf("expected IPAddresses[0] to be empty, got %q", node.IPAddresses[0])
		}
		if node.ServiceTargets == nil || len(node.ServiceTargets) != 1 {
			t.Fatalf("expected ServiceTargets len==1, got %d", len(node.ServiceTargets))
		}

		// Maps: allocated but empty
		if node.Labels == nil {
			t.Fatalf("expected Labels allocated")
		}
		if len(node.Labels) != 0 {
			t.Fatalf("expected Labels empty, got len=%d", len(node.Labels))
		}
		if node.WatchedResources == nil {
			t.Fatalf("expected WatchedResources allocated")
		}
		if len(node.WatchedResources) != 0 {
			t.Fatalf("expected WatchedResources empty, got len=%d", len(node.WatchedResources))
		}

		// Pointers: allocated; contents zero
		if node.Locality == nil || node.Metadata == nil {
			t.Fatalf("expected Locality and Metadata allocated")
		}
		if node.SidecarScope == nil || node.PrevSidecarScope == nil {
			t.Fatalf("expected SidecarScope/PrevSidecarScope allocated")
		}
		if node.MergedGateway == nil || node.PrevMergedGateway == nil {
			t.Fatalf("expected MergedGateway/PrevMergedGateway allocated")
		}
		if node.IstioVersion == nil || node.VerifiedIdentity == nil {
			t.Fatalf("expected IstioVersion/VerifiedIdentity allocated")
		}
		if node.XdsNode == nil || node.LastPushContext == nil {
			t.Fatalf("expected XdsNode/LastPushContext allocated")
		}

		// Interface: nil with insufficient seeds
		if node.XdsResourceGenerator != nil {
			t.Fatalf("expected XdsResourceGenerator to be nil")
		}
	})
}
