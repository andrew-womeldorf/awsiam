package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// Statement is a single statement. Elements that can be a string or an array
// of strings are always represented here as a slice of strings.
//
// https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html
type Statement struct {
	Sid          string                 `json:"Sid,omitempty"`
	Effect       string                 `json:"Effect,omitempty"`
	Principal    map[string]interface{} `json:"Principal,omitempty"`
	NotPrincipal map[string]interface{} `json:"NotPrincipal,omitempty"`
	Action       []string               `json:"Action,omitempty"`
	NotAction    []string               `json:"NotAction,omitempty"`
	Resource     []string               `json:"Resource,omitempty"`
	NotResource  []string               `json:"NotResource,omitempty"`
	Condition    map[string]interface{} `json:"Condition,omitempty"`
}

func (s *Statement) UnmarshalJSON(data []byte) error {
	type statement struct {
		Sid          string                 `json:"Sid,omitempty"`
		Effect       string                 `json:"Effect,omitempty"`
		Principal    map[string]interface{} `json:"Principal,omitempty"`
		NotPrincipal map[string]interface{} `json:"NotPrincipal,omitempty"`
		Action       json.RawMessage        `json:"Action,omitempty"`
		NotAction    json.RawMessage        `json:"NotAction,omitempty"`
		Resource     json.RawMessage        `json:"Resource,omitempty"`
		NotResource  json.RawMessage        `json:"NotResource,omitempty"`
		Condition    map[string]interface{} `json:"Condition,omitempty"`
	}

	var stmt statement
	if err := json.Unmarshal(data, &stmt); err != nil {
		return fmt.Errorf("could not unmarshal statement from json, %w", err)
	}

	s.Sid = stmt.Sid
	s.Effect = stmt.Effect
	s.Principal = stmt.Principal
	s.NotPrincipal = stmt.NotPrincipal
	s.Condition = stmt.Condition

	if len(stmt.Action) > 0 {
		var action interface{}
		if err := json.Unmarshal(stmt.Action, &action); err != nil {
			return fmt.Errorf("could not unmarshal action from json, %w", err)
		}

		switch action.(type) {
		case string:
			s.Action = []string{action.(string)}
		case []interface{}:
			for _, a := range action.([]interface{}) {
				s.Action = append(s.Action, a.(string))
			}
		default:
			return fmt.Errorf("unsupported type for action: %T", action)
		}
	}

	if len(stmt.NotAction) > 0 {
		var action interface{}
		if err := json.Unmarshal(stmt.NotAction, &action); err != nil {
			return fmt.Errorf("could not unmarshal notAction from json, %w", err)
		}

		switch action.(type) {
		case string:
			s.NotAction = []string{action.(string)}
		case []interface{}:
			for _, a := range action.([]interface{}) {
				s.NotAction = append(s.NotAction, a.(string))
			}
		default:
			return fmt.Errorf("unsupported type for notAction: %T", action)
		}
	}

	if len(stmt.Resource) > 0 {
		var resource interface{}
		if err := json.Unmarshal(stmt.Resource, &resource); err != nil {
			return fmt.Errorf("could not unmarshal resource from json, %w", err)
		}

		switch resource.(type) {
		case string:
			s.Resource = []string{resource.(string)}
		case []interface{}:
			for _, r := range resource.([]interface{}) {
				s.Resource = append(s.Resource, r.(string))
			}
		default:
			return fmt.Errorf("unsupported type for resource: %T", resource)
		}
	}

	if len(stmt.NotResource) > 0 {
		var resource interface{}
		if err := json.Unmarshal(stmt.NotResource, &resource); err != nil {
			return fmt.Errorf("could not unmarshal notResource from json, %w", err)
		}

		switch resource.(type) {
		case string:
			s.NotResource = []string{resource.(string)}
		case []interface{}:
			for _, r := range resource.([]interface{}) {
				s.NotResource = append(s.NotResource, r.(string))
			}
		default:
			return fmt.Errorf("unsupported type for notResource: %T", resource)
		}
	}

	return nil
}

type Document struct {
	Version   string
	Id        string `json:"Id,omitempty"`
	Statement []Statement
}

type GetPolicyOutput struct {
	Policy   *types.Policy
	Document Document
}

// GetPolicy retrieves the IAM Policy and the Document at the version defined
// in the Policy. The Document is unmarshaled, into our internal
// representation.
func GetPolicy(ctx context.Context, svc *iam.Client, policyArn *string) (GetPolicyOutput, error) {
	p, err := svc.GetPolicy(ctx, &iam.GetPolicyInput{
		PolicyArn: policyArn,
	})
	if err != nil {
		return GetPolicyOutput{}, fmt.Errorf("failed to get policy, %w", err)
	}

	v, err := svc.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
		PolicyArn: policyArn,
		VersionId: p.Policy.DefaultVersionId,
	})
	if err != nil {
		return GetPolicyOutput{}, fmt.Errorf("failed to get policy version, %w", err)
	}

	documentDecoded, err := url.QueryUnescape(*v.PolicyVersion.Document)
	if err != nil {
		return GetPolicyOutput{}, fmt.Errorf("failed to unescape policy document, %w", err)
	}

	var doc Document
	if err := json.Unmarshal([]byte(documentDecoded), &doc); err != nil {
		return GetPolicyOutput{}, fmt.Errorf("failed to unmarshal policy document, %w", err)
	}

	return GetPolicyOutput{
		Policy:   p.Policy,
		Document: doc,
	}, nil
}

type PolicyDocuments map[string]Document

func GetPoliciesForRole(ctx context.Context, svc *iam.Client, roleName *string) (PolicyDocuments, error) {
	policies := make(PolicyDocuments)

	attached, err := svc.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: roleName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list attached role policies, %w", err)
	}

	for _, policy := range attached.AttachedPolicies {
		p, err := GetPolicy(ctx, svc, policy.PolicyArn)
		if err != nil {
			return nil, fmt.Errorf("failed to get policy with document, %w", err)
		}
		policies[*p.Policy.PolicyName] = p.Document
	}

	inline, err := svc.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: roleName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list role policies, %w", err)
	}

	for _, policy := range inline.PolicyNames {
		p, err := svc.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			PolicyName: aws.String(policy),
			RoleName:   roleName,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to get role policy, %w", err)
		}

		var doc Document
		if err := json.Unmarshal([]byte(*p.PolicyDocument), &doc); err != nil {
			return nil, fmt.Errorf("failed to unmarshal role policy document, %w", err)
		}

		policies[policy] = doc
	}

	return policies, nil
}

// FilterPolicies only returns policies that have actions that start with the
// filter string and only the actions which match the filter.
func FilterPolicies(policies PolicyDocuments, filter string) PolicyDocuments {
	filtered := make(PolicyDocuments)

	for name, doc := range policies {
		for _, stmt := range doc.Statement {
			actions := make([]string, 0)
			for _, action := range stmt.Action {
				if action == filter || action[:len(filter)] == filter {
					actions = append(actions, action)
				}
			}

			if len(actions) > 0 {
				stmt.Action = actions
				doc.Statement = []Statement{stmt}
				filtered[name] = doc
			}
		}
	}

	return filtered
}

func main() {
	ctx := context.Background()
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("unable to load SDK config, %v", err)
	}

	svc := iam.NewFromConfig(cfg)

	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <rolename>", os.Args[0])
	}
	rolename := os.Args[1]

	policies, err := GetPoliciesForRole(ctx, svc, aws.String(rolename))
	if err != nil {
		log.Fatalf("failed to get policies for role, %v", err)
	}

	var filter string
	if len(os.Args) == 3 {
		filter = os.Args[2]
	}

	if filter != "" {
		policies = FilterPolicies(policies, filter)
	}

	b, err := json.Marshal(policies)
	if err != nil {
		log.Fatalf("failed to marshal policies, %v", err)
	}
	fmt.Println(string(b))
}
