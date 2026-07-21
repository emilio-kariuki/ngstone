package edge

import (
	"errors"
	"math/rand/v2"
	"regexp"
	"strconv"
)

const maxRandomAttempts = 20

var subdomainRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

var subdomainDenylist = map[string]bool{
	"www":      true,
	"mail":     true,
	"ns1":      true,
	"ns2":      true,
	"admin":    true,
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

func assignRandomHostname(r *Registry, as *AgentSession, takeover bool, domain string, genName func() string) (hostname string, evicted *AgentSession, err error) {
	for attempt := 0; attempt < maxRandomAttempts; attempt++ {
		candidate := genName()
		hostname = candidate + "." + domain
		_, evicted, err = r.Bind(hostname, as, takeover)
		if err == nil {
			return hostname, evicted, nil
		}
		if !errors.Is(err, ErrSubdomainTaken) {
			return "", nil, err
		}
	}
	return "", nil, errNoFreeName
}
