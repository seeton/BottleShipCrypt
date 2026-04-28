package bship

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
)

type trustedStore struct {
	Format   string               `json:"format"`
	Archives []trustedStoreRecord `json:"archives"`
}

type trustedStoreRecord struct {
	ArchiveID string `json:"archive_id"`
	Version   uint64 `json:"version"`
	Root      string `json:"root"`
	WrapKey   string `json:"wrap_key_b64"`
}

func verifyTrustedState(path string, archive *Archive) error {
	record, err := trustedRecord(path, archive)
	if err != nil {
		return err
	}
	if record.Version != archive.State.Version || record.Root != archive.State.CurrentRoot {
		return fmt.Errorf("%w: trusted version=%d root=%s archive version=%d root=%s",
			errStaleArchiveState, record.Version, record.Root, archive.State.Version, archive.State.CurrentRoot)
	}
	return nil
}

func trustedWrapKey(path string, archive *Archive) ([]byte, error) {
	record, err := trustedRecord(path, archive)
	if err != nil {
		return nil, err
	}
	if record.WrapKey == "" {
		return nil, fmt.Errorf("trusted state for archive %s is missing wrap key", archive.Manifest.ArchiveID)
	}
	key, err := decodeBase64URL(record.WrapKey)
	if err != nil {
		return nil, fmt.Errorf("decode trusted wrap key: %w", err)
	}
	return key, nil
}

func trustedRecord(path string, archive *Archive) (trustedStoreRecord, error) {
	store, err := readTrustedStore(path)
	if err != nil {
		return trustedStoreRecord{}, err
	}
	record, ok := store.lookup(archive.Manifest.ArchiveID)
	if !ok {
		return trustedStoreRecord{}, fmt.Errorf("%w: missing trusted state for archive %s", errStaleArchiveState, archive.Manifest.ArchiveID)
	}
	return record, nil
}

func updateTrustedStore(path, archiveID string, version uint64, root, wrapKey string, createOnly bool) error {
	store, err := readTrustedStore(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if errors.Is(err, os.ErrNotExist) {
		store = trustedStore{Format: trustedStoreFormat}
	}
	if store.Format == "" {
		store.Format = trustedStoreFormat
	}
	if store.Format != trustedStoreFormat {
		return fmt.Errorf("unsupported trusted store format %q", store.Format)
	}

	if record, ok := store.lookup(archiveID); ok {
		if createOnly {
			return fmt.Errorf("trusted state for archive %s already exists", archiveID)
		}
		if version <= record.Version {
			return fmt.Errorf("trusted state version must increase: current=%d next=%d", record.Version, version)
		}
		if wrapKey == "" {
			wrapKey = record.WrapKey
		}
		store.replace(trustedStoreRecord{ArchiveID: archiveID, Version: version, Root: root, WrapKey: wrapKey})
	} else {
		store.Archives = append(store.Archives, trustedStoreRecord{ArchiveID: archiveID, Version: version, Root: root, WrapKey: wrapKey})
		slices.SortFunc(store.Archives, func(a, b trustedStoreRecord) int {
			switch {
			case a.ArchiveID < b.ArchiveID:
				return -1
			case a.ArchiveID > b.ArchiveID:
				return 1
			default:
				return 0
			}
		})
	}
	return writeTrustedStore(path, store)
}

func readTrustedStore(path string) (trustedStore, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return trustedStore{}, err
	}
	var store trustedStore
	if err := json.Unmarshal(data, &store); err != nil {
		return trustedStore{}, fmt.Errorf("parse trusted store: %w", err)
	}
	if store.Format != "" && store.Format != trustedStoreFormat {
		return trustedStore{}, fmt.Errorf("unsupported trusted store format %q", store.Format)
	}
	return store, nil
}

func writeTrustedStore(path string, store trustedStore) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal trusted store: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write trusted store: %w", err)
	}
	return nil
}

func (s trustedStore) lookup(archiveID string) (trustedStoreRecord, bool) {
	for _, record := range s.Archives {
		if record.ArchiveID == archiveID {
			return record, true
		}
	}
	return trustedStoreRecord{}, false
}

func (s *trustedStore) replace(record trustedStoreRecord) {
	for i := range s.Archives {
		if s.Archives[i].ArchiveID == record.ArchiveID {
			s.Archives[i] = record
			return
		}
	}
	s.Archives = append(s.Archives, record)
}
