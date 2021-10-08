package mysql

import "time"

// SendPackets tx packets
type SendPackets struct {
	Datetime     time.Time `json:"time"`
	ConnectionID uint32    `json:"id,omitempty"`
	User         string    `json:"user,omitempty"`
	Db           string    `json:"db,omitempty"`
	Addr         string    `json:"addr,omitempty"`
	State        string    `json:"state,omitempty"`   // 5
	Err          string    `json:"err,omitempty"`     // 6
	Packets      []byte    `json:"packets,omitempty"` // 7
	Cmd          string    `json:"cmd,omitempty"`
	buf          []byte
}
