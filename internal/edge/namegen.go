package edge

import (
	"errors"
	"math/rand/v2"
	"regexp"
	"strconv"

	"ngstone/internal/policy"
)

const maxRandomAttempts = 20

var subdomainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

var subdomainDenylist = map[string]bool{
	"www":      true,
	"mail":     true,
	"ns1":      true,
	"ns2":      true,
	"admin":    true,
	"dev":      true,
	"api-edge": true,
}

func validSubdomain(name string) bool {
	if subdomainDenylist[name] {
		return false
	}
	return subdomainRE.MatchString(name)
}

var nameAdjectives = []string{
	"amber", "brisk", "calm", "cobalt", "daring", "eager", "faint", "gentle",
	"honest", "icy", "jolly", "keen", "lively", "mellow", "nimble", "olive",
	"plain", "quiet", "rapid", "silver", "tidy", "vivid", "witty", "young",
}

var nameNouns = []string{
	"fox", "otter", "comet", "harbor", "lynx", "meadow", "pebble", "quartz",
	"raven", "summit", "tiger", "willow", "canyon", "delta", "ember", "falcon",
	"glade", "heron", "island", "juniper",
}

func randomSubdomain() string {
	adj := nameAdjectives[rand.IntN(len(nameAdjectives))]
	noun := nameNouns[rand.IntN(len(nameNouns))]
	n := rand.IntN(100)
	return adj + "-" + noun + "-" + strconv.Itoa(n)
}

var errNoFreeName = errors.New("edge: could not assign a free subdomain")

type hostnameOptions struct {
	Session              *AgentSession
	Takeover             bool
	Domain               string
	Generate             func() string
	Access               *accessControl
	TrafficPolicy        *policy.Policy
	HTTP2                bool
	MultiConnector       bool
	ConnectorTokenDigest string
}

func assignRandomHostname(r *Registry, opts hostnameOptions) (hostname string, evicted *AgentSession, err error) {
	for attempt := 0; attempt < maxRandomAttempts; attempt++ {
		candidate := opts.Generate()
		hostname = candidate + "." + opts.Domain
		_, evicted, err = r.BindWithOptions(BindOptions{
			Host:                 hostname,
			Session:              opts.Session,
			Takeover:             opts.Takeover,
			Access:               opts.Access,
			TrafficPolicy:        opts.TrafficPolicy,
			HTTP2:                opts.HTTP2,
			MultiConnector:       opts.MultiConnector,
			ConnectorTokenDigest: opts.ConnectorTokenDigest,
		})
		if err == nil {
			return hostname, evicted, nil
		}
		if !errors.Is(err, ErrSubdomainTaken) && !errors.Is(err, ErrConnectorConfigMismatch) {
			return "", nil, err
		}
	}
	return "", nil, errNoFreeName
}
