/*
 * Copyright 2022 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package podfingerprint

import (
	"encoding/json"
	"math/rand"
	"testing"
	"time"
)

func TestNamespacedNameString(t *testing.T) {
	nn := NamespacedName{
		Namespace: "foo",
		Name:      "bar",
	}

	expected := "foo/bar"
	got := nn.String()
	if got != expected {
		t.Errorf("string failed: got %q expected %q", got, expected)
	}
}

func TestNamespacedNameGetters(t *testing.T) {
	nn := NamespacedName{
		Namespace: "foo",
		Name:      "bar",
	}

	nsGot := nn.GetNamespace()
	nGot := nn.GetName()
	if nsGot != "foo" || nGot != "bar" {
		t.Errorf("getters failed: %q vs %q and %q vs %q", nsGot, "foo", nGot, "bar")
	}
}

var expectedStatusJson string = `{"fingerprintExpected":"pfp0v001b92008c14168b3a6","fingerprintComputed":"pfp0v001b92008c14168b3a6","pods":[{"Namespace":"ns1","Name":"n1"},{"Namespace":"ns1","Name":"n2"},{"Namespace":"ns2","Name":"n1"},{"Namespace":"ns3","Name":"n1"},{"Namespace":"ns3","Name":"n2"}]}`

func TestTraceStatusJSON(t *testing.T) {
	pods := []NamespacedName{
		{
			Namespace: "ns1",
			Name:      "n1",
		},
		{
			Namespace: "ns1",
			Name:      "n2",
		},
		{
			Namespace: "ns2",
			Name:      "n1",
		},
		{
			Namespace: "ns3",
			Name:      "n1",
		},
		{
			Namespace: "ns3",
			Name:      "n2",
		},
	}

	st := Status{}
	fp := NewTracingFingerprint(len(pods), &st)
	for _, pod := range pods {
		fp.Add(pod.Namespace, pod.Name)
	}
	fp.Sign()
	err := fp.Check("pfp0v001b92008c14168b3a6")
	if err != nil {
		t.Fatalf("fp check error: %v", err)
	}

	data, err := json.Marshal(st)
	if err != nil {
		t.Fatalf("JSON marshal error: %v", err)
	}
	got := string(data)
	if got != expectedStatusJson {
		t.Errorf("status report error.\ngot: %s\nexp: %s", got, expectedStatusJson)
	}
}

var expectedStatusRepr = `> processing node "test-node"
> processing 5 pods
+ ns1/n1
+ ns1/n2
+ ns2/n1
+ ns3/n1
+ ns3/n2
= pfp0v001b92008c14168b3a6
V pfp0v001b92008c14168b3a6
`

func TestTraceStatusRepr(t *testing.T) {
	pods := []NamespacedName{
		{
			Namespace: "ns1",
			Name:      "n1",
		},
		{
			Namespace: "ns1",
			Name:      "n2",
		},
		{
			Namespace: "ns2",
			Name:      "n1",
		},
		{
			Namespace: "ns3",
			Name:      "n1",
		},
		{
			Namespace: "ns3",
			Name:      "n2",
		},
	}

	st := MakeStatus("test-node")
	fp := NewTracingFingerprint(len(pods), &st)
	for _, pod := range pods {
		fp.Add(pod.Namespace, pod.Name)
	}
	fp.Sign()
	err := fp.Check("pfp0v001b92008c14168b3a6")
	if err != nil {
		t.Fatalf("fp check error: %v", err)
	}

	got := st.Repr()
	if got != expectedStatusRepr {
		t.Errorf("status repr error.\ngot: %s\nexp: %s", got, expectedStatusRepr)
	}
}

func TestSignCrosscheck(t *testing.T) {
	if len(pods) == 0 || podsErr != nil {
		t.Fatalf("cannot load the test data: %v", podsErr)
	}

	localPods := make([]NamespacedName, len(pods))
	copy(localPods, pods)
	rand.Shuffle(len(localPods), func(i, j int) {
		localPods[i], localPods[j] = localPods[j], localPods[i]
	})

	fp := NewFingerprint(0)
	for _, pod := range pods {
		fp.Add(pod.Namespace, pod.Name)
	}
	fp2 := NewTracingFingerprint(0, NullTracer{})
	for _, localPod := range localPods {
		fp2.Add(localPod.Namespace, localPod.Name)
	}

	x := fp.Sign()
	x2 := fp2.Sign()
	if x != x2 {
		t.Fatalf("signature not stable: %q vs %q", x, x2)
	}
}

func TestStatusClone(t *testing.T) {
	orig := Status{
		FingerprintExpected: "PFPExpectedOrig",
		FingerprintComputed: "PFPComputedOrig",
		Pods: []NamespacedName{
			{
				Namespace: "NSOrig1",
				Name:      "Name1",
			},
			{
				Namespace: "NSOrig2",
				Name:      "Name2",
			},
		},
	}

	cloned := orig.Clone()

	origData, err := json.Marshal(orig)
	if err != nil {
		t.Errorf("marshal orig failed: %v", err)
	}
	clonedData, err := json.Marshal(cloned)
	if err != nil {
		t.Errorf("marshal cloned failed: %v", err)
	}
	if string(origData) != string(clonedData) {
		t.Errorf("clone not identical:\norig=%s\ncloned=%s", string(origData), string(clonedData))
	}

	cloned.FingerprintComputed = "PFPModified2"
	cloned.Pods = append(cloned.Pods, NamespacedName{
		Namespace: "NSModified2",
		Name:      "NameModified2",
	})

	origData2, err := json.Marshal(orig)
	if err != nil {
		t.Errorf("marshal orig (2) failed: %v", err)
	}

	if string(origData) != string(origData2) {
		t.Errorf("original modified changing the clone!\norig=%s\norig2=%s", string(origData), string(origData2))
	}
}

func TestStatusEqual(t *testing.T) {
	X := Status{
		FingerprintExpected: "PFPExpectedOrig",
		FingerprintComputed: "PFPComputedOrig",
		Pods: []NamespacedName{
			{
				Namespace: "NSOrig1",
				Name:      "Name1",
			},
			{
				Namespace: "NSOrig2",
				Name:      "Name2",
			},
		},
		NodeName: "Node",
	}
	testCases := []struct {
		Desc     string
		Y        Status
		Expected bool
	}{
		{
			Desc: "clone",
			Y: Status{
				FingerprintExpected: "PFPExpectedOrig",
				FingerprintComputed: "PFPComputedOrig",
				Pods: []NamespacedName{
					{
						Namespace: "NSOrig1",
						Name:      "Name1",
					},
					{
						Namespace: "NSOrig2",
						Name:      "Name2",
					},
				},
				NodeName: "Node",
			},
			Expected: true,
		},
		{
			Desc: "diff: nodeName",
			Y: Status{
				FingerprintExpected: "PFPExpectedOrig",
				FingerprintComputed: "PFPComputedOrig",
				Pods: []NamespacedName{
					{
						Namespace: "NSOrig1",
						Name:      "Name1",
					},
					{
						Namespace: "NSOrig2",
						Name:      "Name2",
					},
				},
				NodeName: "NodeFooBar",
			},
			Expected: false,
		},
		{
			Desc: "diff: pfp Expected",
			Y: Status{
				FingerprintExpected: "PFPExpectedDIFF",
				FingerprintComputed: "PFPComputedOrig",
				Pods: []NamespacedName{
					{
						Namespace: "NSOrig1",
						Name:      "Name1",
					},
					{
						Namespace: "NSOrig2",
						Name:      "Name2",
					},
				},
				NodeName: "Node",
			},
			Expected: false,
		},
		{
			Desc: "diff: pfp Computed",
			Y: Status{
				FingerprintExpected: "PFPExpectedOrig",
				FingerprintComputed: "PFPComputedDiff",
				Pods: []NamespacedName{
					{
						Namespace: "NSOrig1",
						Name:      "Name1",
					},
					{
						Namespace: "NSOrig2",
						Name:      "Name2",
					},
				},
				NodeName: "Node",
			},
			Expected: false,
		},
		{
			Desc: "diff: pod count",
			Y: Status{
				FingerprintExpected: "PFPExpectedOrig",
				FingerprintComputed: "PFPComputedDiff",
				Pods: []NamespacedName{
					{
						Namespace: "NSOrig2",
						Name:      "Name2",
					},
				},
				NodeName: "Node",
			},
			Expected: false,
		},
		{
			Desc: "diff: pod values",
			Y: Status{
				FingerprintExpected: "PFPExpectedOrig",
				FingerprintComputed: "PFPComputedDiff",
				Pods: []NamespacedName{
					{
						Namespace: "NSOrig5",
						Name:      "Name5",
					},
					{
						Namespace: "NSOrigX",
						Name:      "NameX",
					},
				},
				NodeName: "Node",
			},
			Expected: false,
		},
		{
			Desc: "diff: pod missing",
			Y: Status{
				FingerprintExpected: "PFPExpectedOrig",
				FingerprintComputed: "PFPComputedDiff",
				NodeName:            "Node",
			},
			Expected: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.Desc, func(t *testing.T) {
			got := X.Equal(tc.Y)
			if got != tc.Expected {
				t.Fatalf("got=%v expected=%v", got, tc.Expected)
			}
		})

	}
}

func TestSeal(t *testing.T) {
	st := MakeStatus("node-1")
	st.Sign("PFPComputed")
	start := time.Now()
	time.Sleep(3 * time.Second)
	end := time.Now()
	expectedDuration := end.Sub(start)
	st.Seal()
	if st.Duration.Round(time.Second) != expectedDuration.Round(time.Second) {
		t.Errorf("seal error: expected %v, got %v", expectedDuration, st.Duration)
	}
}
