package app

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/croessner/opendkim-manage-go/internal/dkim2store"
)

func loadRetentionJournal(path string, maximumBytes int) (dkim2store.GenerationPurgePlan, []byte, bool, error) {
	if err := validateRetentionJournalDirectory(path); err != nil {
		return dkim2store.GenerationPurgePlan{}, nil, false, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return dkim2store.GenerationPurgePlan{}, nil, false, nil
	}
	if maximumBytes < 1 || err != nil || !safeOwnedRegularFile(info, 0o600) || info.Size() < 1 || info.Size() > int64(maximumBytes) {
		return dkim2store.GenerationPurgePlan{}, nil, false, errors.New("DKIM2 retention journal is unavailable or unsafe")
	}
	file, err := os.Open(path)
	if err != nil {
		return dkim2store.GenerationPurgePlan{}, nil, false, errors.New("DKIM2 retention journal is unavailable or unsafe")
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return dkim2store.GenerationPurgePlan{}, nil, false, errors.New("DKIM2 retention journal changed during read")
	}
	document, err := io.ReadAll(io.LimitReader(file, int64(maximumBytes)+1))
	if err != nil || len(document) > maximumBytes {
		return dkim2store.GenerationPurgePlan{}, nil, false, errors.New("DKIM2 retention journal is unavailable")
	}
	plan, err := dkim2store.ParseGenerationPurgePlan(document, maximumBytes)
	if err != nil {
		clear(document)
		return dkim2store.GenerationPurgePlan{}, nil, false, errors.New("DKIM2 retention journal is malformed")
	}
	return plan, document, true, nil
}

func createRetentionJournal(path string, maximumBytes int, plan dkim2store.GenerationPurgePlan) ([]byte, error) {
	if err := validateRetentionJournalDirectory(path); err != nil {
		return nil, err
	}
	document, err := dkim2store.MarshalGenerationPurgePlan(plan)
	if maximumBytes < 1 || err != nil || len(document) > maximumBytes {
		return nil, errors.New("DKIM2 retention plan is malformed")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		clear(document)
		return nil, errors.New("DKIM2 retention journal already exists or cannot be created")
	}
	completed := false
	defer func() {
		_ = file.Close()
		if !completed {
			_ = os.Remove(path)
		}
	}()
	info, err := file.Stat()
	if err != nil || !safeOwnedRegularFile(info, 0o600) {
		clear(document)
		return nil, errors.New("DKIM2 retention journal is unsafe")
	}
	if _, err := file.Write(document); err != nil || file.Sync() != nil || file.Close() != nil {
		clear(document)
		return nil, errors.New("DKIM2 retention journal could not be durably written")
	}
	completed = true
	return document, nil
}

func removeRetentionJournal(path string, maximumBytes int, expected []byte) error {
	plan, observed, present, err := loadRetentionJournal(path, maximumBytes)
	_ = plan
	if err != nil || !present || !bytes.Equal(observed, expected) {
		clear(observed)
		return errors.New("DKIM2 retention journal changed before completion")
	}
	clear(observed)
	if err := os.Remove(path); err != nil {
		return errors.New("DKIM2 retention journal could not be removed")
	}
	return nil
}

func validateRetentionJournalDirectory(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("DKIM2 retention journal path is invalid")
	}
	info, err := os.Lstat(filepath.Dir(path))
	if err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !ownedByEffectiveUser(info) {
		return errors.New("DKIM2 retention journal directory is unavailable or unsafe")
	}
	return nil
}

func safeOwnedRegularFile(info os.FileInfo, permission os.FileMode) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == permission && ownedByEffectiveUser(info)
}

func ownedByEffectiveUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
