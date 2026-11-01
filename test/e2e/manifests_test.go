// Copyright 2026 The Agent Substrate Authors
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

// Package e2e holds the end-to-end test fixtures that hack/e2e-kind.sh feeds
// to kubectl-ate. This test decodes them into substrate's API types, so a
// misspelled or misplaced field fails here rather than on a cluster.
package e2e

import (
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"sigs.k8s.io/yaml"

	"go.ate.dev/substrate/api/ateapi/v1"
)

// decode reads a fixture, substitutes the script's placeholders, and decodes
// it strictly into msg.
func decode(t *testing.T, path string, msg proto.Message, subst ...string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc := strings.NewReplacer(subst...).Replace(string(raw))
	js, err := yaml.YAMLToJSON([]byte(doc))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if err := (protojson.UnmarshalOptions{}).Unmarshal(js, msg); err != nil {
		t.Fatalf("%s does not decode as %T: %v", path, msg, err)
	}
}

func TestActorTemplateFixture(t *testing.T) {
	var tmpl ateapi.ActorTemplate
	decode(t, "actor-template.yaml", &tmpl, "ATESPACE", "team-a", "PROBE_IMAGE", "localhost:5001/probe@sha256:0")
	if tmpl.GetMetadata().GetAtespace() != "team-a" || tmpl.GetMetadata().GetName() != "probe" {
		t.Errorf("metadata = %v", tmpl.GetMetadata())
	}
	if got := tmpl.GetSnapshotConfig().GetGoldenSnapshotConfig().GetMode(); got != ateapi.GoldenSnapshotMode_GOLDEN_SNAPSHOT_MODE_DISABLED {
		t.Errorf("golden snapshot mode = %v, want disabled", got)
	}
	if len(tmpl.GetContainers()) != 1 || tmpl.GetContainers()[0].GetWakeupProbe().GetHttpGet().GetPort() != 80 {
		t.Errorf("containers = %v, want one with a wakeup probe on port 80", tmpl.GetContainers())
	}
}

func TestEgressPolicyFixture(t *testing.T) {
	const uri = "ate-secret://openbao/kv/secret/atespaces/team-a/example-api/token"
	var policy ateapi.EgressPolicy
	decode(t, "egress-policy.yaml", &policy, "TARGET_HOST", "whoami.credprovider-openbao-e2e.svc.cluster.local", "CREDENTIAL_URI", uri)
	rules := policy.GetRules()
	if len(rules) != 1 || rules[0].GetHttp() == nil {
		t.Fatalf("rules = %v, want one http rule", rules)
	}
	headers := rules[0].GetHttp().GetEffects().GetReplaceHeaders()
	if len(headers) != 1 || headers[0].GetHeader() != "Authorization" || headers[0].GetPrefix() != "Bearer " || headers[0].GetCredentialUri() != uri {
		t.Errorf("replace headers = %v", headers)
	}
}
