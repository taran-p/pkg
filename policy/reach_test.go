// Copyright (c) 2015-2026 MinIO, Inc.
//
// This file is part of MinIO Object Storage stack
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package policy

import (
	"net"
	"strings"
	"testing"

	"github.com/minio/pkg/v3/policy/condition"
)

func TestPolicyReach(t *testing.T) {
	testCases := []struct {
		name   string
		policy string
		action Action
		want   Reach
	}{
		{
			name:   "no statements",
			policy: `{"Version":"2012-10-17","Statement":[]}`,
			action: ListBucketAction,
			want:   ReachNone,
		},
		{
			name: "allow on one bucket",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::bucket1"]}]}`,
			action: ListBucketAction,
			want:   ReachPossible,
		},
		{
			name: "allow names another action",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::*"]}]}`,
			action: ListBucketAction,
			want:   ReachNone,
		},
		{
			name: "allow with a condition",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::*"],
				 "Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`,
			action: ListBucketAction,
			want:   ReachPossible,
		},
		{
			name: "allow by NotAction",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","NotAction":["s3:PutObject"],"Resource":["arn:aws:s3:::*"]}]}`,
			action: ListBucketAction,
			want:   ReachPossible,
		},
		{
			name: "NotAction excludes the action",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","NotAction":["s3:PutObject"],"Resource":["arn:aws:s3:::*"]}]}`,
			action: PutObjectAction,
			want:   ReachNone,
		},
		{
			name: "deny on one bucket leaves the rest",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]},
				{"Effect":"Deny","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::bucket1"]}]}`,
			action: ListBucketAction,
			want:   ReachPossible,
		},
		{
			name: "deny on every S3 resource",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]},
				{"Effect":"Deny","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::*"]}]}`,
			action: ListBucketAction,
			want:   ReachDenied,
		},
		{
			name: "deny on the bare wildcard",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]},
				{"Effect":"Deny","Action":["s3:*"],"Resource":["*"]}]}`,
			action: ListBucketAction,
			want:   ReachDenied,
		},
		{
			name: "deny without an allow",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Deny","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::*"]}]}`,
			action: ListBucketAction,
			want:   ReachDenied,
		},
		{
			name: "deny on objects only",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]},
				{"Effect":"Deny","Action":["s3:*"],"Resource":["arn:aws:s3:::*/*"]}]}`,
			action: ListBucketAction,
			want:   ReachPossible,
		},
		{
			name: "deny with a policy variable",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]},
				{"Effect":"Deny","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::${aws:username}"]}]}`,
			action: ListBucketAction,
			want:   ReachPossible,
		},
		{
			name: "deny with a condition",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]},
				{"Effect":"Deny","Action":["s3:ListBucket"],"Resource":["arn:aws:s3:::*"],
				 "Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`,
			action: ListBucketAction,
			want:   ReachPossible,
		},
		{
			name: "deny by NotResource",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]},
				{"Effect":"Deny","Action":["s3:ListBucket"],"NotResource":["arn:aws:s3:::bucket1"]}]}`,
			action: ListBucketAction,
			want:   ReachPossible,
		},
		{
			name: "deny by NotAction",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3:*"],"Resource":["arn:aws:s3:::*"]},
				{"Effect":"Deny","NotAction":["s3:GetObject"],"Resource":["arn:aws:s3:::*"]}]}`,
			action: ListBucketAction,
			want:   ReachDenied,
		},
		{
			name: "admin deny ignores resources",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["admin:*"]},
				{"Effect":"Deny","Action":["admin:ListUsers"]}]}`,
			action: Action(ListUsersAdminAction),
			want:   ReachDenied,
		},
		{
			name: "bucket-scoped admin deny on one bucket",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["admin:*"]},
				{"Effect":"Deny","Action":["admin:SetBucketQuota"],"Resource":["arn:aws:s3:::bucket1"]}]}`,
			action: Action(SetBucketQuotaAdminAction),
			want:   ReachPossible,
		},
		{
			name: "bucket-scoped admin deny on every bucket",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["admin:*"]},
				{"Effect":"Deny","Action":["admin:SetBucketQuota"],"Resource":["arn:aws:s3:::*"]}]}`,
			action: Action(SetBucketQuotaAdminAction),
			want:   ReachDenied,
		},
		{
			name: "STS deny",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["sts:AssumeRole"],"Resource":["arn:aws:s3:::*"]},
				{"Effect":"Deny","Action":["sts:AssumeRole"],"Resource":["arn:aws:s3:::bucket1"]}]}`,
			action: Action(AssumeRoleAction),
			want:   ReachDenied,
		},
		{
			name: "KMS deny without resources",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["kms:*"]},
				{"Effect":"Deny","Action":["kms:CreateKey"]}]}`,
			action: Action(KMSCreateKeyAction),
			want:   ReachDenied,
		},
		{
			name: "KMS deny on one key",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["kms:*"]},
				{"Effect":"Deny","Action":["kms:CreateKey"],"Resource":["arn:minio:kms:::key1"]}]}`,
			action: Action(KMSCreateKeyAction),
			want:   ReachPossible,
		},
		{
			name: "tables allow implies the S3 data action",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:GetTableData"],"Resource":["arn:aws:s3tables:::*"]}]}`,
			action: GetObjectAction,
			want:   ReachPossible,
		},
		{
			name: "tables deny reaches only the tables form",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::*"]},
				{"Effect":"Deny","Action":["s3tables:GetTableData"],"Resource":["arn:aws:s3tables:::*"]}]}`,
			action: GetObjectAction,
			want:   ReachPossible,
		},
		{
			name: "tables deny on every table",
			policy: `{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Action":["s3tables:*"],"Resource":["arn:aws:s3tables:::*"]},
				{"Effect":"Deny","Action":["s3tables:GetTable"],"Resource":["arn:aws:s3tables:::*"]}]}`,
			action: Action(S3TablesGetTableAction),
			want:   ReachDenied,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := ParseConfig(strings.NewReader(tc.policy))
			if err != nil {
				t.Fatalf("parsing policy: %v", err)
			}
			if got := p.Reach(tc.action); got != tc.want {
				t.Errorf("Reach(%s) = %d, want %d", tc.action, got, tc.want)
			}
		})
	}
}

// TestPolicyReachSound checks Reach against Decide over every resource form the
// policy language accepts: a policy Reach rules out must never allow, and one
// it reports denied must deny every request.
func TestPolicyReachSound(t *testing.T) {
	_, ipNet, err := net.ParseCIDR("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	ipCond, err := condition.NewIPAddressFunc(condition.AWSSourceIP.ToKey(), ipNet)
	if err != nil {
		t.Fatal(err)
	}
	conditionSets := []condition.Functions{condition.NewFunctions(), condition.NewFunctions(ipCond)}

	actionSets := []ActionSet{
		NewActionSet(ListBucketAction),
		NewActionSet(AllActions),
		NewActionSet(GetObjectAction),
		NewActionSet(Action(ListUsersAdminAction)),
		NewActionSet(Action(SetBucketQuotaAdminAction)),
		NewActionSet(Action(KMSCreateKeyAction)),
		NewActionSet(Action(AssumeRoleAction)),
		NewActionSet(Action(S3TablesGetTableDataAction)),
		NewActionSet(Action(AllS3TablesActions)),
	}

	resourceSets := []ResourceSet{NewResourceSet()}
	for _, value := range acceptedResourceCorpus {
		r, err := ParseResource(value)
		if err != nil {
			t.Fatalf("parsing %q: %v", value, err)
		}
		resourceSets = append(resourceSets, NewResourceSet(r))
	}

	var statements []Statement
	for _, effect := range []Effect{Allow, Deny} {
		for _, actions := range actionSets {
			for _, conds := range conditionSets {
				for _, resources := range resourceSets {
					statements = append(statements,
						NewStatement("", effect, actions, resources, conds),
						NewStatementWithNotAction("", effect, actions, resources, conds))
				}
				statements = append(statements,
					NewStatementWithNotResource("", effect, actions, NewResourceStrings("bucket"), conds))
			}
		}
	}

	queried := []Action{
		ListBucketAction,
		GetObjectAction,
		PutObjectAction,
		Action(ListUsersAdminAction),
		Action(SetBucketQuotaAdminAction),
		Action(KMSCreateKeyAction),
		Action(AssumeRoleAction),
		Action(S3TablesGetTableDataAction),
		Action(S3TablesGetTableAction),
	}

	targets := []struct{ bucket, object string }{
		{"", ""},
		{"bucket", ""},
		{"bucket", "key"},
		{"bucket", "a/b/c"},
		{"bucket", "wh/table/id"},
		{"other", ""},
		{"alice", "x"},
		{"cortex", "agents/alpha"},
	}
	conditionValues := []map[string][]string{
		{condition.AWSUsername.Name(): {"alice"}, condition.AWSSourceIP.Name(): {"192.168.1.10"}},
		{condition.AWSUsername.Name(): {"bob"}, condition.AWSSourceIP.Name(): {"10.0.0.1"}},
	}

	check := func(p *Policy) {
		t.Helper()
		p.Reindex()
		for _, action := range queried {
			reach := p.Reach(action)
			if reach == ReachPossible {
				continue
			}
			for _, target := range targets {
				for _, values := range conditionValues {
					args := Args{
						Action:          action,
						BucketName:      target.bucket,
						ObjectName:      target.object,
						ConditionValues: values,
					}
					decision := p.Decide(&args)
					if decision == AllowDecision || (reach == ReachDenied && decision != DenyDecision) {
						t.Fatalf("Reach(%s) = %d but Decide(%s/%s, %v) = %d for policy %+v",
							action, reach, target.bucket, target.object, values, decision, p.Statements)
					}
				}
			}
		}
	}

	for _, statement := range statements {
		check(&Policy{Version: DefaultVersion, Statements: []Statement{statement}})
		allowAll := NewStatement("", Allow, statement.Actions, NewResourceStrings("*"), condition.NewFunctions())
		check(&Policy{Version: DefaultVersion, Statements: []Statement{allowAll, statement}})
	}
}
