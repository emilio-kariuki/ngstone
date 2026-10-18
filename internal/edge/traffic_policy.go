package edge

import (
	"fmt"

	"ngstone/internal/policy"
	"ngstone/internal/proto"
)

func buildTrafficPolicy(bind proto.Bind) (*policy.Policy, error) {
	if bind.Policy == nil {
		if bind.PolicyDigest != "" {
			return nil, fmt.Errorf("traffic policy digest provided without a policy")
		}
		return nil, nil
	}
	if err := bind.Policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid traffic policy: %w", err)
	}
	if bind.PolicyDigest == "" || bind.Policy.Digest() != bind.PolicyDigest {
		return nil, fmt.Errorf("traffic policy digest does not match policy")
	}
	return bind.Policy, nil
}
