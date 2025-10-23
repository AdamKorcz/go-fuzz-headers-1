package gofuzzheaders

import (
	"encoding/hex"
	"fmt"
	"reflect"
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
