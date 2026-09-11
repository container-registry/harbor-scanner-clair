package job

import (
	"encoding/json"

	"github.com/container-registry/harbor-scanner-clair/pkg/harbor"
)

type ScanJobStatus int

const (
	Queued ScanJobStatus = iota
	Pending
	Finished
	Failed
)

// scanJobStatusNames is indexed by ScanJobStatus. String bounds against its
// length rather than a literal, so adding a status cannot silently start
// rendering as "Unknown".
var scanJobStatusNames = [...]string{
	"Queued",
	"Pending",
	"Finished",
	"Failed",
}

func (s ScanJobStatus) String() string {
	if s < 0 || int(s) >= len(scanJobStatusNames) {
		return "Unknown"
	}
	return scanJobStatusNames[s]
}

// ScanJob is the persisted job record. It is keyed by a plain scan job id: this
// adapter produces exactly one MIME type, so the composite {id, mime, media}
// key the SBOM-capable adapters need would carry no information here. If SBOM
// output is ever added, the composite key comes back.
//
// Report holds the pre-marshaled report envelope (json.RawMessage) so it is
// never re-marshaled on a report poll.
//
// Request is the scan Harbor asked for. It is part of the record rather than of
// a separate queue message because the record is the queue entry: a worker
// claims a row and gets everything it needs to run the scan from it, so there is
// no second write that could disagree with the first.
type ScanJob struct {
	ID      string             `json:"id"`
	Status  ScanJobStatus      `json:"status"`
	Error   string             `json:"error"`
	Report  json.RawMessage    `json:"report,omitempty"`
	Request harbor.ScanRequest `json:"request"`
}
