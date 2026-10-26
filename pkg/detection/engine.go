package detection

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Engine manages detection rules, event correlation, and backtesting.
type Engine struct {
	mu           sync.RWMutex
	Rules        []*Rule
	Correlation  *Correlation
	AuthScanners map[string]bool
	ThresholdGTE int
	Timespan     time.Duration
}

// NewEngine initializes a detection engine with default parameters.
func NewEngine() *Engine {
	return &Engine{
		Rules:        make([]*Rule, 0),
		AuthScanners: make(map[string]bool),
		ThresholdGTE: 12,
		Timespan:     10 * time.Minute,
	}
}

// LoadRulesFromYAML parses one or multiple YAML documents in a rule file.
func (e *Engine) LoadRulesFromYAML(data []byte) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	dec := yaml.NewDecoder(bytes.NewReader(data))
	e.Rules = make([]*Rule, 0)
	e.AuthScanners = make(map[string]bool)

	for {
		var r Rule
		err := dec.Decode(&r)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("yaml decode error: %w", err)
		}

		if r.Correlation != nil {
			e.Correlation = r.Correlation
			if r.Correlation.Condition.GTE > 0 {
				e.ThresholdGTE = r.Correlation.Condition.GTE
			}
			if r.Correlation.Timespan != "" {
				if d, err := time.ParseDuration(r.Correlation.Timespan); err == nil {
					e.Timespan = d
				}
			}
		}

		// Extract filter_authorised_scanners if present
		if r.Detection != nil {
			if scanners, ok := r.Detection["filter_authorised_scanners"].(map[string]interface{}); ok {
				if ips, ok := scanners["SourceIP"].([]interface{}); ok {
					for _, ip := range ips {
						e.AuthScanners[fmt.Sprintf("%v", ip)] = true
					}
				}
			}
		}

		e.Rules = append(e.Rules, &r)
	}

	return nil
}

// SetAuthorizedScanners updates excluded scanner IPs.
func (e *Engine) SetAuthorizedScanners(ips []string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.AuthScanners = make(map[string]bool)
	for _, ip := range ips {
		e.AuthScanners[strings.TrimSpace(ip)] = true
	}
}

// SetThreshold updates the distinct account threshold for correlation.
func (e *Engine) SetThreshold(threshold int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ThresholdGTE = threshold
	if e.Correlation != nil {
		e.Correlation.Condition.GTE = threshold
	}
}

// IsAuthorizedScanner checks if an IP is in the scanner exemption list.
func (e *Engine) IsAuthorizedScanner(ip string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.AuthScanners[ip]
}

// MatchesSelection checks if an event matches the base detection selection criteria.
func (e *Engine) MatchesSelection(ev Event) bool {
	// Base rule: NPS / RADIUS VPN access denied (EventID: 6273)
	if ev.Product != "" && !strings.EqualFold(ev.Product, "windows") {
		return false
	}
	if ev.Service != "" && !strings.EqualFold(ev.Service, "nps") {
		return false
	}
	if ev.EventID != 0 && ev.EventID != 6273 {
		return false
	}

	// Filter out authorized scanners
	if e.IsAuthorizedScanner(ev.SourceIP) {
		return false
	}

	// Filter internal loopback or private bypass if specified
	if ev.SourceIP == "" {
		return false
	}

	return true
}

// CorrelatedAlert represents an alert generated after correlation logic fires.
type CorrelatedAlert struct {
	RuleTitle       string    `json:"ruleTitle"`
	SourceIP        string    `json:"sourceIP"`
	DistinctTarget  int       `json:"distinctTargetCount"`
	TargetAccounts  []string  `json:"targetAccounts"`
	FirstSeen       time.Time `json:"firstSeen"`
	LastSeen        time.Time `json:"lastSeen"`
	FiredAt         time.Time `json:"firedAt"`
	IsFalsePositive bool      `json:"isFalsePositive"`
	Reason          string    `json:"reason"`
}

// EvaluateBatch processes a stream of events through the sliding correlation window.
func (e *Engine) EvaluateBatch(events []Event) []CorrelatedAlert {
	e.mu.RLock()
	threshold := e.ThresholdGTE
	timespan := e.Timespan
	e.mu.RUnlock()

	if threshold <= 0 {
		threshold = 12
	}
	if timespan <= 0 {
		timespan = 10 * time.Minute
	}

	// Group matching events by SourceIP within timespan
	type ipWindow struct {
		events []Event
	}

	windows := make(map[string]*ipWindow)
	var alerts []CorrelatedAlert
	firedWindows := make(map[string]bool)

	for _, ev := range events {
		if !e.MatchesSelection(ev) {
			continue
		}

		w, ok := windows[ev.SourceIP]
		if !ok {
			w = &ipWindow{events: make([]Event, 0)}
			windows[ev.SourceIP] = w
		}

		w.events = append(w.events, ev)

		// Trim events outside the timespan window relative to current event
		cutoff := ev.Timestamp.Add(-timespan)
		var valid []Event
		accountSet := make(map[string]bool)
		for _, prev := range w.events {
			if prev.Timestamp.After(cutoff) || prev.Timestamp.Equal(cutoff) {
				valid = append(valid, prev)
				if prev.TargetUserName != "" {
					accountSet[prev.TargetUserName] = true
				}
			}
		}
		w.events = valid

		// Check correlation condition: distinct target accounts >= threshold
		distinctCount := len(accountSet)
		windowKey := fmt.Sprintf("%s_%s", ev.SourceIP, ev.Timestamp.Truncate(timespan).String())

		if distinctCount >= threshold && !firedWindows[windowKey] {
			firedWindows[windowKey] = true

			var accounts []string
			for acc := range accountSet {
				accounts = append(accounts, acc)
			}

			// Heuristic triage flag: check if source IP is known NAT gateway with typical business day logins
			isFP := isOfficeNAT(ev.SourceIP)
			reason := "Password spraying pattern detected across distinct accounts"
			if isFP {
				reason = "Shared office NAT traffic burst"
			}

			alerts = append(alerts, CorrelatedAlert{
				RuleTitle:       "Correlation - many accounts, one source IP",
				SourceIP:        ev.SourceIP,
				DistinctTarget:  distinctCount,
				TargetAccounts:  accounts,
				FirstSeen:       valid[0].Timestamp,
				LastSeen:        ev.Timestamp,
				FiredAt:         ev.Timestamp,
				IsFalsePositive: isFP,
				Reason:          reason,
			})
		}
	}

	return alerts
}

func isOfficeNAT(ip string) bool {
	// Standard simulated office NAT for triage demonstration
	return ip == "198.51.100.45" || ip == "203.0.113.19"
}

// ParseIP validates standard IPv4 or IPv6
func ParseIP(s string) net.IP {
	return net.ParseIP(s)
}
