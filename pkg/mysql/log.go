package mysql

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"
)

type auditLogs struct {
	FileName   string
	Gzip       bool
	RotateTime time.Duration
	Queue      chan *SendPackets
	Bs         *buffers

	gz io.WriteCloser
	f  *os.File
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

func (a *auditLogs) openStream(t time.Time) (f io.WriteCloser, err error) {
	name := time2Path(a.FileName, t)
	if a.Gzip {
		name = name + ".gz"
	}
	a.f, err = os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}
	if !a.Gzip {
		return a.f, nil
	}
	a.gz = gzip.NewWriter(a.f)
	return a.gz, nil
}
func (a *auditLogs) closeStream() (err error) {
	if a.gz != nil {
		err = a.gz.Close()
		if err != nil {
			return
		}
		a.gz = nil
	}
	if a.f == nil {
		return nil
	}
	err = a.f.Close()
	if err != nil {
		return err
	}
	a.f = nil
	return nil
}

func (a auditLogs) logWorker(ctx context.Context, res chan error) {
	var err error
	var w io.Writer
	defer func() { a.closeStream(); res <- err; close(res) }()
	if w, err = a.openStream(time.Now()); err != nil {
		return
	}
	e := json.NewEncoder(w)
	tt := time.NewTicker(a.RotateTime)
	defer tt.Stop()
	for {
		select {
		case t := <-tt.C:
			if err = a.closeStream(); err != nil {
				return
			}
			if w, err = a.openStream(t); err != nil {
				return
			}
			e = json.NewEncoder(w)
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
