package storage

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"central-flow-collector/internal/model"
)

var walMagic = []byte("CFCWAL1\n")

const walRecordOverhead = 8

func encodeWALSegment(flows []model.Flow) ([]byte, error) {
	var b bytes.Buffer
	b.Grow(len(walMagic) + len(flows)*256)
	_, _ = b.Write(walMagic)
	var hdr [8]byte
	for _, f := range flows {
		rec, err := json.Marshal(f)
		if err != nil {
			return nil, err
		}
		if len(rec) == 0 || len(rec) > 4<<20 {
			return nil, fmt.Errorf("WAL record size %d out of bounds", len(rec))
		}
		binary.BigEndian.PutUint32(hdr[0:4], uint32(len(rec)))
		binary.BigEndian.PutUint32(hdr[4:8], crc32.ChecksumIEEE(rec))
		_, _ = b.Write(hdr[:])
		_, _ = b.Write(rec)
	}
	return b.Bytes(), nil
}

func decodeWAL(r io.Reader) ([]model.Flow, error) {
	br := bufio.NewReaderSize(r, 1<<20)
	magic := make([]byte, len(walMagic))
	if _, err := io.ReadFull(br, magic); err != nil {
		return nil, err
	}
	if !bytes.Equal(magic, walMagic) {
		return nil, errors.New("invalid WAL magic")
	}
	out := []model.Flow{}
	var hdr [8]byte
	for {
		_, err := io.ReadFull(br, hdr[:])
		if errors.Is(err, io.EOF) {
			break
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, errors.New("truncated WAL record header")
		}
		if err != nil {
			return nil, err
		}
		n := binary.BigEndian.Uint32(hdr[0:4])
		want := binary.BigEndian.Uint32(hdr[4:8])
		if n == 0 || n > 4<<20 {
			return nil, fmt.Errorf("invalid WAL record length %d", n)
		}
		rec := make([]byte, n)
		if _, err := io.ReadFull(br, rec); err != nil {
			return nil, fmt.Errorf("truncated WAL record: %w", err)
		}
		if got := crc32.ChecksumIEEE(rec); got != want {
			return nil, fmt.Errorf("WAL CRC mismatch got=%08x want=%08x", got, want)
		}
		var f model.Flow
		if err := json.Unmarshal(rec, &f); err != nil {
			return nil, fmt.Errorf("decode WAL flow: %w", err)
		}
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil, errors.New("empty WAL segment")
	}
	return out, nil
}

func (c *ClickHouse) writeSpoolFile(name string, data []byte) error {
	if err := os.MkdirAll(c.spoolDir, 0750); err != nil {
		return err
	}
	tmp := filepath.Join(c.spoolDir, name+".tmp")
	final := filepath.Join(c.spoolDir, name)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if c.cfg.SpoolFsync {
		if err = f.Sync(); err != nil {
			return err
		}
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, final); err != nil {
		return err
	}
	if c.cfg.SpoolFsync {
		if d, e := os.Open(c.spoolDir); e == nil {
			_ = d.Sync()
			_ = d.Close()
		}
	}
	ok = true
	return nil
}

func (c *ClickHouse) spoolBatch(batch []model.Flow) error {
	if !c.cfg.SpoolEnabled || len(batch) == 0 {
		return fmt.Errorf("clickhouse spool disabled")
	}
	segMax := c.cfg.SpoolSegmentBytes
	if segMax < 1<<20 {
		segMax = 64 << 20
	}
	segments := [][]byte{}
	start := 0
	for start < len(batch) {
		// grow a segment until the next record would exceed the configured segment size.
		end := start + 1
		best, err := encodeWALSegment(batch[start:end])
		if err != nil {
			return err
		}
		for end < len(batch) {
			candidate, er := encodeWALSegment(batch[start : end+1])
			if er != nil {
				return er
			}
			if int64(len(candidate)) > segMax {
				break
			}
			best = candidate
			end++
		}
		if int64(len(best)) > segMax && end == start+1 {
			return fmt.Errorf("single WAL record exceeds segment size")
		}
		segments = append(segments, best)
		start = end
	}
	var newBytes int64
	for _, x := range segments {
		newBytes += int64(len(x))
	}
	if c.cfg.SpoolMaxBytes > 0 {
		_, used, _ := c.spoolUsage()
		if used+newBytes > c.cfg.SpoolMaxBytes {
			return fmt.Errorf("clickhouse spool quota exceeded: used=%d new=%d max=%d", used, newBytes, c.cfg.SpoolMaxBytes)
		}
	}
	seqBase := c.spoolSeq.Add(uint64(len(segments)))
	writtenSegments := []string{}
	for i, data := range segments {
		seq := seqBase - uint64(len(segments)-1-i)
		name := fmt.Sprintf("%020d-%06d.wal", time.Now().UTC().UnixNano(), seq%1_000_000)
		if err := c.writeSpoolFile(name, data); err != nil {
			// Preserve any already committed segments: they are valid recovery data.
			return fmt.Errorf("write WAL segment after %d committed segments: %w", len(writtenSegments), err)
		}
		writtenSegments = append(writtenSegments, name)
	}
	c.spooled.Add(uint64(len(batch)))
	return nil
}

func (c *ClickHouse) spoolUsage() (files int, bytesN int64, err error) {
	entries, err := os.ReadDir(c.spoolDir)
	if os.IsNotExist(err) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".wal" && ext != ".jsonl" {
			continue
		}
		info, e2 := e.Info()
		if e2 != nil {
			continue
		}
		files++
		bytesN += info.Size()
	}
	return
}

func readLegacyJSONL(path string) ([]model.Flow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 4<<20)
	out := []model.Flow{}
	for sc.Scan() {
		var flow model.Flow
		if err := json.Unmarshal(sc.Bytes(), &flow); err != nil {
			return nil, err
		}
		out = append(out, flow)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, errors.New("empty legacy spool file")
	}
	return out, nil
}
func readWALFile(path string) ([]model.Flow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return decodeWAL(f)
}

func (c *ClickHouse) quarantineSpool(path string, reason error) {
	dir := filepath.Join(c.spoolDir, "corrupt")
	_ = os.MkdirAll(dir, 0750)
	base := filepath.Base(path)
	dst := filepath.Join(dir, fmt.Sprintf("%s.%d.bad", base, time.Now().UTC().UnixNano()))
	if os.Rename(path, dst) == nil {
		c.spoolQuarantined.Add(1)
	}
	c.spoolCorrupt.Add(1)
	c.setError(fmt.Errorf("quarantined corrupt spool %s: %w", base, reason))
}

func (c *ClickHouse) replaySpoolOne() {
	if !c.cfg.SpoolEnabled {
		return
	}
	entries, err := os.ReadDir(c.spoolDir)
	if err != nil {
		return
	}
	names := []string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext == ".wal" || ext == ".jsonl" {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return
	}
	sort.Strings(names)
	path := filepath.Join(c.spoolDir, names[0])
	var batch []model.Flow
	if strings.HasSuffix(names[0], ".wal") {
		batch, err = readWALFile(path)
	} else {
		batch, err = readLegacyJSONL(path)
		if err == nil {
			c.spoolLegacy.Add(1)
		}
	}
	if err != nil {
		c.quarantineSpool(path, err)
		return
	}
	if err = c.sendBatch(batch); err != nil {
		c.setError(err)
		c.healthy.Store(false)
		return
	}
	if os.Remove(path) == nil {
		c.replayed.Add(uint64(len(batch)))
	}
}

// recoverSpoolTemps promotes only fully valid crash-leftover WAL .tmp files and
// quarantines incomplete ones. It is intentionally conservative: legacy JSONL
// temporary files are never promoted automatically.
func (c *ClickHouse) recoverSpoolTemps() {
	entries, err := os.ReadDir(c.spoolDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".wal.tmp") {
			continue
		}
		p := filepath.Join(c.spoolDir, e.Name())
		if _, er := readWALFile(p); er != nil {
			c.quarantineSpool(p, er)
			continue
		}
		final := strings.TrimSuffix(p, ".tmp")
		if _, er := os.Stat(final); er == nil {
			c.quarantineSpool(p, errors.New("target WAL already exists"))
			continue
		}
		if os.Rename(p, final) == nil {
			c.spoolRecovered.Add(1)
		}
	}
}
