package edge

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"ngstone/internal/policy"
	"ngstone/internal/proto"
	"ngstone/internal/storage"
)

type durableAccessRecord struct {
	BasicAuthSHA256 []string `json:"basic_auth_sha256,omitempty"`
	BasicAuthRealm  string   `json:"basic_auth_realm,omitempty"`
	AllowCIDRs      []string `json:"allow_cidrs,omitempty"`
}

func durableLeaseKey(kind, hostname string, remotePort int) string {
	return strings.ToLower(strings.TrimSpace(kind)) + ":" + strings.ToLower(strings.TrimSpace(hostname)) + ":" + strconv.Itoa(remotePort)
}

func durableOwnerID(as *AgentSession) string {
	if as != nil && as.Credential != nil && as.Credential.ID != "" {
		if as.Credential.OwnerID != "" {
			return as.Credential.OwnerID
		}
		return as.Credential.ID
	}
	return "legacy"
}

func durableAccessJSON(bind proto.Bind) string {
	data, err := json.Marshal(durableAccessRecord{
		BasicAuthSHA256: bind.BasicAuthSHA256,
		BasicAuthRealm:  bind.BasicAuthRealm,
		AllowCIDRs:      bind.AllowCIDRs,
	})
	if err != nil {
		return "{}"
	}
	return string(data)
}

func (s *Server) acquireDurableLease(as *AgentSession, bind proto.Bind, hostname string, remotePort int, trafficPolicy *policy.Policy) (storage.Lease, error) {
	if s.storage == nil {
		return storage.Lease{}, nil
	}
	kind := "http"
	if bind.Kind == proto.KindTCP {
		kind = "tcp"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return s.storage.AcquireLease(ctx, storage.LeaseRequest{
		Name:                 bind.Name,
		Hostname:             hostname,
		Kind:                 kind,
		RemotePort:           remotePort,
		OwnerID:              durableOwnerID(as),
		InstanceID:           as.InstanceID,
		SessionID:            as.ID,
		EdgeID:               s.storage.EdgeID(),
		Takeover:             bind.Takeover,
		HTTP2:                bind.HTTP2,
		MultiConnector:       bind.MultiConnector,
		ConnectorTokenDigest: bind.ConnectorTokenSHA256,
		AllowCIDRsJSON:       mustJSON(bind.AllowCIDRs, "[]"),
		AccessJSON:           durableAccessJSON(bind),
		Policy:               trafficPolicy,
		PolicyDigest:         bind.PolicyDigest,
	})
}

func mustJSON(value any, fallback string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return fallback
	}
	return string(encoded)
}

func (as *AgentSession) rememberDurableLease(key, id string) {
	if as == nil || id == "" {
		return
	}
	as.leaseMu.Lock()
	if as.durableLeases == nil {
		as.durableLeases = make(map[string]string)
	}
	if _, exists := as.durableLeases[key]; !exists {
		as.durableLeaseNum.Add(1)
	}
	as.durableLeases[key] = id
	as.leaseMu.Unlock()
}

func (as *AgentSession) forgetDurableLease(key string) string {
	if as == nil {
		return ""
	}
	as.leaseMu.Lock()
	defer as.leaseMu.Unlock()
	id := as.durableLeases[key]
	if id != "" {
		delete(as.durableLeases, key)
		as.durableLeaseNum.Add(-1)
	}
	return id
}

func (as *AgentSession) clearDurableLeases() {
	if as == nil {
		return
	}
	as.leaseMu.Lock()
	as.durableLeases = nil
	as.durableLeaseNum.Store(0)
	as.leaseMu.Unlock()
}

func (s *Server) releaseDurableLease(as *AgentSession, key string, leaseID string) {
	if s.storage == nil {
		return
	}
	if leaseID == "" {
		leaseID = as.forgetDurableLease(key)
	} else {
		as.forgetDurableLease(key)
	}
	if leaseID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.storage.ReleaseLease(ctx, leaseID); err != nil {
		slogStorageError("release connector lease", err)
	}
}

func (s *Server) releaseDurableSession(as *AgentSession) {
	if s.storage == nil || as == nil {
		return
	}
	as.clearDurableLeases()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.storage.ReleaseSession(ctx, s.storage.EdgeID(), as.ID); err != nil {
		slogStorageError("release session leases", err)
	}
}

func (s *Server) renewDurableSession(as *AgentSession) error {
	if s.storage == nil || as == nil || as.durableLeaseNum.Load() == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	count, err := s.storage.RenewSessionLeases(ctx, s.storage.EdgeID(), as.ID, time.Now())
	if err != nil {
		return err
	}
	if count == 0 {
		return storage.ErrLeaseLost
	}
	return nil
}

func durableLeaseError(err error) (string, string) {
	switch {
	case errors.Is(err, storage.ErrTunnelConflict):
		return proto.CodeSubdomainTaken, "tunnel name is already in use"
	case errors.Is(err, storage.ErrConnectorConfigMismatch):
		return proto.CodeConnectorConfigMismatch, "connector settings do not match the existing tunnel"
	case errors.Is(err, storage.ErrLeaseLost):
		return proto.CodeInternal, "connector lease is no longer active"
	default:
		slogStorageError("acquire connector lease", err)
		return proto.CodeInternal, "durable storage operation failed"
	}
}

func slogStorageError(operation string, err error) {
	if err != nil {
		slog.Warn("edge: durable storage operation failed", "operation", operation, "err", err)
	}
}
