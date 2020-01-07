package mysql

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

type auditLogs struct {
	FileName   string
	RotateTime time.Duration
	Queue      chan *SendPackets
	Bs         *buffers
}

/*
func truncate(t time.Time, d time.Duration) time.Time {
	if d == 24*time.Hour {
		return t.Truncate(time.Hour).Add(-time.Duration(t.Hour()) * time.Hour)
	}
	return t.Truncate(d)
}
*/

// /path/to/mysql-audit.%Y%m%d%H.log
func time2Path(p string, t time.Time) string {
	p = strings.Replace(p, "%Y", fmt.Sprintf("%04d", t.Year()), -1)
	p = strings.Replace(p, "%y", fmt.Sprintf("%02d", t.Year()%100), -1)
	p = strings.Replace(p, "%m", fmt.Sprintf("%02d", t.Month()), -1)
	p = strings.Replace(p, "%d", fmt.Sprintf("%02d", t.Day()), -1)
	p = strings.Replace(p, "%H", fmt.Sprintf("%02d", t.Hour()), -1)
	p = strings.Replace(p, "%M", fmt.Sprintf("%02d", t.Minute()), -1)
	p = strings.Replace(p, "%S", fmt.Sprintf("%02d", t.Second()), -1)
	return p
}

func (a auditLogs) logWorker(ctx context.Context, res chan error) {
	var err error
	var f *os.File
	defer func() { res <- err; close(res) }()
	if f, err = os.Create(time2Path(a.FileName, time.Now())); err != nil {
		return
	}
	defer f.Close()
	e := json.NewEncoder(f)
	tt := time.NewTicker(a.RotateTime)
	defer tt.Stop()
	for {
		select {
		case t := <-tt.C:
			f.Close()
			name := time2Path(a.FileName, t)
			f, err = os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
			if err != nil {
				return
			}
			e = json.NewEncoder(f)
		case <-ctx.Done():
			for p := range a.Queue {
				if err = e.Encode(p); err != nil {
					return
				}
				a.Bs.Put(p)
			}
			log.Println("Log flush completed.")
			return
		case p, ok := <-a.Queue:
			if !ok {
				return
			}
			if err = e.Encode(p); err != nil {
				return
			}
			a.Bs.Put(p)
		}
	}
}
