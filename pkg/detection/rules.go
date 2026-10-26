package detection

import "time"

// Rule represents a Sigma-style detection rule and correlation rule definition.
type Rule struct {
	Title       string                 `yaml:"title" json:"title"`
	Name        string                 `yaml:"name" json:"name"`
	Description string                 `yaml:"description,omitempty" json:"description,omitempty"`
	Status      string                 `yaml:"status,omitempty" json:"status,omitempty"`
	Logsource   Logsource              `yaml:"logsource,omitempty" json:"logsource,omitempty"`
	Detection   map[string]interface{} `yaml:"detection,omitempty" json:"detection,omitempty"`
	Correlation *Correlation           `yaml:"correlation,omitempty" json:"correlation,omitempty"`
	Level       string                 `yaml:"level,omitempty" json:"level,omitempty"`
	Tags        []string               `yaml:"tags,omitempty" json:"tags,omitempty"`
}

// Logsource specifies product, service, and category for incoming telemetry.
type Logsource struct {
	Product  string `yaml:"product" json:"product"`
	Service  string `yaml:"service" json:"service"`
	Category string `yaml:"category,omitempty" json:"category,omitempty"`
}

// Correlation defines cross-event correlation logic (e.g. threshold over timespan).
type Correlation struct {
	Type      string        `yaml:"type" json:"type"` // e.g. value_count, sequence
	Rules     []string      `yaml:"rules" json:"rules"`
	GroupBy   []string      `yaml:"group-by" json:"groupBy"`
	Timespan  string        `yaml:"timespan" json:"timespan"`
	Condition CorrCondition `yaml:"condition" json:"condition"`
}

// CorrCondition defines the threshold check for correlation.
type CorrCondition struct {
	Field string `yaml:"field" json:"field"`
	GTE   int    `yaml:"gte" json:"gte"`
}

// Event represents a single normalized telemetry log entry.
type Event struct {
	Timestamp      time.Time              `json:"timestamp"`
	Product        string                 `json:"product"`
	Service        string                 `json:"service"`
	EventID        int                    `json:"EventID,omitempty"`
	SourceIP       string                 `json:"SourceIP,omitempty"`
	TargetUserName string                 `json:"TargetUserName,omitempty"`
	Action         string                 `json:"action,omitempty"`
	Raw            map[string]interface{} `json:"raw,omitempty"`
}

// TestCase represents an attack or benign replay case.
type TestCase struct {
	Replay string `yaml:"replay" json:"replay"`
	Expect string `yaml:"expect" json:"expect"` // "fire" or "quiet"
	Note   string `yaml:"note,omitempty" json:"note,omitempty"`
}

// TestSuite represents a set of replay test cases for a detection.
type TestSuite struct {
	Cases []TestCase `yaml:"cases" json:"cases"`
}

// ReplayResult holds the execution outcome of unit test replays.
type ReplayResult struct {
	CaseName string `json:"caseName"`
	Expect   string `json:"expect"`
	Actual   string `json:"actual"`
	Passed   bool   `json:"passed"`
	Events   int    `json:"events"`
	FiredAt  string `json:"firedAt,omitempty"`
}

// BacktestResult summarizes historical telemetry evaluation.
type BacktestResult struct {
	Stage1ReplaysTotal   int            `json:"stage1ReplaysTotal"`
	Stage1ReplaysPassed  int            `json:"stage1ReplaysPassed"`
	Stage1AttacksFired   string         `json:"stage1AttacksFired"`
	Stage1BenignQuiet    string         `json:"stage1BenignQuiet"`
	Stage2TotalEvents    int            `json:"stage2TotalEvents"`
	Stage2Days           int            `json:"stage2Days"`
	FiresCount           int            `json:"firesCount"`
	TriagedBenign        int            `json:"triagedBenign"`
	FalsePositives       int            `json:"falsePositives"`
	FalsePositiveBudget  int            `json:"falsePositiveBudget"`
	WithinBudget         bool           `json:"withinBudget"`
	TuningRecommendation string         `json:"tuningRecommendation,omitempty"`
	Details              []ReplayResult `json:"details"`
}
