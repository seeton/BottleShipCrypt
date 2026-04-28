package bship

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

const archiveFormat = "bship-json-v1"
const trustedStoreFormat = "bship-trusted-store-v1"
const nonceSize = 12
const keySize = 32

var (
	errThresholdExceeded = errors.New("remaining plaintext exceeds threshold")
	errDestroyedCapsule  = errors.New("chunk capsule has been destroyed")
	errStaleArchiveState = errors.New("archive state does not match trusted store")
)

type Mode string

const (
	WeakMode        Mode = "weak"
	StrongMode      Mode = "simulated-strong"
	StrongModeAlias Mode = "strong"
)

type Archive struct {
	Format   string        `json:"format"`
	Manifest Manifest      `json:"manifest"`
	State    ArchiveState  `json:"state"`
	Chunks   []StoredChunk `json:"chunks"`
	Capsules []Capsule     `json:"capsules"`
}

type Manifest struct {
	ArchiveID           string          `json:"archive_id"`
	SourceName          string          `json:"source_name"`
	ThresholdBytes      int64           `json:"threshold_bytes"`
	ChunkSizeBytes      int             `json:"chunk_size_bytes"`
	TotalPlaintextBytes int64           `json:"total_plaintext_bytes"`
	CreatedAt           string          `json:"created_at"`
	Crypto              CryptoSuite     `json:"crypto"`
	Chunks              []ChunkManifest `json:"chunks"`
	ManifestHash        string          `json:"manifest_hash"`
}

type CryptoSuite struct {
	ChunkAEAD   string `json:"chunk_aead"`
	CapsuleAEAD string `json:"capsule_aead"`
	Hash        string `json:"hash"`
}

type ChunkManifest struct {
	ID             string `json:"id"`
	Index          int    `json:"index"`
	Offset         int64  `json:"offset"`
	PlaintextSize  int    `json:"plaintext_size"`
	CiphertextSize int    `json:"ciphertext_size"`
	CiphertextHash string `json:"ciphertext_hash"`
	CapsuleHash    string `json:"capsule_hash"`
	Destroyed      bool   `json:"destroyed"`
}

type ArchiveState struct {
	ArchiveID            string   `json:"archive_id"`
	Version              uint64   `json:"version"`
	RemainingChunkIDs    []string `json:"remaining_chunk_ids"`
	RemainingPlaintext   int64    `json:"remaining_plaintext_bytes"`
	ThresholdBytes       int64    `json:"threshold_bytes"`
	CurrentRoot          string   `json:"current_root"`
	CapsuleWrapKeyBase64 string   `json:"capsule_wrap_key_b64"`
}

type StoredChunk struct {
	ID          string `json:"id"`
	NonceBase64 string `json:"nonce_b64"`
	Ciphertext  string `json:"ciphertext_b64"`
}

type Capsule struct {
	ChunkID     string `json:"chunk_id"`
	Destroyed   bool   `json:"destroyed"`
	NonceBase64 string `json:"nonce_b64"`
	Ciphertext  string `json:"ciphertext_b64"`
}

type SealOptions struct {
	InputPath        string
	ArchivePath      string
	ThresholdBytes   int64
	ChunkSizeBytes   int
	Mode             Mode
	TrustedStorePath string
	ArchiveID        string
	Now              func() time.Time
	Rand             io.Reader
}

type InspectOptions struct {
	ArchivePath      string
	Mode             Mode
	TrustedStorePath string
}

type PruneOptions struct {
	ArchivePath      string
	Keep             []string
	Mode             Mode
	TrustedStorePath string
}

type DecryptOptions struct {
	ArchivePath      string
	OutputPath       string
	Mode             Mode
	TrustedStorePath string
}

type Inspection struct {
	ArchiveID            string   `json:"archive_id"`
	Version              uint64   `json:"version"`
	ThresholdBytes       int64    `json:"threshold_bytes"`
	TotalPlaintextBytes  int64    `json:"total_plaintext_bytes"`
	RemainingPlaintext   int64    `json:"remaining_plaintext_bytes"`
	ChunkSizeBytes       int      `json:"chunk_size_bytes"`
	TotalChunks          int      `json:"total_chunks"`
	RemainingChunks      int      `json:"remaining_chunks"`
	DestroyedChunkIDs    []string `json:"destroyed_chunk_ids"`
	RemainingChunkIDs    []string `json:"remaining_chunk_ids"`
	Decryptable          bool     `json:"decryptable"`
	CurrentRoot          string   `json:"current_root"`
	TrustedStoreVerified bool     `json:"trusted_store_verified"`
}

func SealFile(opts SealOptions) (*Archive, error) {
	if opts.InputPath == "" {
		return nil, errors.New("seal requires --in")
	}
	if opts.ArchivePath == "" {
		return nil, errors.New("seal requires --out")
	}
	if opts.ThresholdBytes < 0 {
		return nil, errors.New("threshold must be >= 0")
	}
	if opts.ChunkSizeBytes <= 0 {
		return nil, errors.New("chunk size must be > 0")
	}

	mode, err := normalizeMode(opts.Mode)
	if err != nil {
		return nil, err
	}
	random := opts.Rand
	if random == nil {
		random = rand.Reader
	}
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	plaintext, err := os.ReadFile(opts.InputPath)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}

	archiveID := opts.ArchiveID
	if archiveID == "" {
		archiveID, err = randomArchiveID(random)
		if err != nil {
			return nil, err
		}
	}

	wrapKey, err := randomBytes(random, keySize)
	if err != nil {
		return nil, fmt.Errorf("generate capsule wrap key: %w", err)
	}

	manifest := Manifest{
		ArchiveID:           archiveID,
		SourceName:          filepath.Base(opts.InputPath),
		ThresholdBytes:      opts.ThresholdBytes,
		ChunkSizeBytes:      opts.ChunkSizeBytes,
		TotalPlaintextBytes: int64(len(plaintext)),
		CreatedAt:           nowFn().UTC().Format(time.RFC3339),
		Crypto: CryptoSuite{
			ChunkAEAD:   "AES-GCM-256",
			CapsuleAEAD: "AES-GCM-256",
			Hash:        "SHA-256",
		},
	}

	var chunks []StoredChunk
	var capsules []Capsule
	var remaining []string

	for offset, index := 0, 0; offset < len(plaintext) || (len(plaintext) == 0 && index == 0); index++ {
		var part []byte
		if len(plaintext) == 0 {
			part = []byte{}
			offset = 1
		} else {
			end := min(offset+opts.ChunkSizeBytes, len(plaintext))
			part = plaintext[offset:end]
			offset = end
		}

		chunkID := fmt.Sprintf("chunk-%04d", index)
		chunkKey, err := randomBytes(random, keySize)
		if err != nil {
			return nil, fmt.Errorf("generate chunk key: %w", err)
		}
		chunkNonce, err := randomBytes(random, nonceSize)
		if err != nil {
			return nil, fmt.Errorf("generate chunk nonce: %w", err)
		}
		chunkCiphertext, err := sealAESGCM(chunkKey, chunkNonce, part, mustJSON(chunkAAD{
			Type:          "chunk",
			ArchiveID:     archiveID,
			ChunkID:       chunkID,
			Index:         index,
			PlaintextSize: len(part),
		}))
		if err != nil {
			return nil, fmt.Errorf("seal chunk %s: %w", chunkID, err)
		}
		chunk := StoredChunk{
			ID:          chunkID,
			NonceBase64: encodeBase64URL(chunkNonce),
			Ciphertext:  encodeBase64URL(chunkCiphertext),
		}

		capsuleNonce, err := randomBytes(random, nonceSize)
		if err != nil {
			return nil, fmt.Errorf("generate capsule nonce: %w", err)
		}
		wrappedKey, err := sealAESGCM(wrapKey, capsuleNonce, chunkKey, mustJSON(capsuleAAD{
			Type:      "capsule",
			ArchiveID: archiveID,
			ChunkID:   chunkID,
		}))
		if err != nil {
			return nil, fmt.Errorf("seal capsule %s: %w", chunkID, err)
		}
		capsule := Capsule{
			ChunkID:     chunkID,
			Destroyed:   false,
			NonceBase64: encodeBase64URL(capsuleNonce),
			Ciphertext:  encodeBase64URL(wrappedKey),
		}

		manifest.Chunks = append(manifest.Chunks, ChunkManifest{
			ID:             chunkID,
			Index:          index,
			Offset:         int64(index * opts.ChunkSizeBytes),
			PlaintextSize:  len(part),
			CiphertextSize: len(chunkCiphertext),
			CiphertextHash: hashBlob(chunkNonce, chunkCiphertext),
			CapsuleHash:    hashBlob(capsuleNonce, wrappedKey),
			Destroyed:      false,
		})
		chunks = append(chunks, chunk)
		capsules = append(capsules, capsule)
		remaining = append(remaining, chunkID)
	}

	if len(plaintext) == 0 {
		manifest.TotalPlaintextBytes = 0
	}

	manifest.ManifestHash = computeManifestHash(manifest)
	state := ArchiveState{
		ArchiveID:            archiveID,
		Version:              0,
		RemainingChunkIDs:    append([]string(nil), remaining...),
		RemainingPlaintext:   manifest.TotalPlaintextBytes,
		ThresholdBytes:       opts.ThresholdBytes,
		CapsuleWrapKeyBase64: encodeBase64URL(wrapKey),
	}
	if mode == StrongMode {
		state.CapsuleWrapKeyBase64 = ""
	}
	state.CurrentRoot = computeStateRoot(state, manifest)

	archive := &Archive{
		Format:   archiveFormat,
		Manifest: manifest,
		State:    state,
		Chunks:   chunks,
		Capsules: capsules,
	}
	if err := writeArchive(opts.ArchivePath, archive); err != nil {
		return nil, err
	}

	if mode == StrongMode {
		storePath := trustedStorePathFor(opts.ArchivePath, opts.TrustedStorePath)
		if err := updateTrustedStore(storePath, archive.Manifest.ArchiveID, archive.State.Version, archive.State.CurrentRoot, encodeBase64URL(wrapKey), true); err != nil {
			return nil, err
		}
	}
	return archive, nil
}

func InspectArchive(opts InspectOptions) (*Inspection, error) {
	archive, err := loadArchive(opts.ArchivePath)
	if err != nil {
		return nil, err
	}
	mode, err := normalizeMode(opts.Mode)
	if err != nil {
		return nil, err
	}
	verified := false
	if mode == StrongMode {
		storePath := trustedStorePathFor(opts.ArchivePath, opts.TrustedStorePath)
		if err := verifyTrustedState(storePath, archive); err != nil {
			return nil, err
		}
		verified = true
	}

	destroyed := make([]string, 0)
	for _, chunk := range archive.Manifest.Chunks {
		if chunk.Destroyed {
			destroyed = append(destroyed, chunk.ID)
		}
	}

	return &Inspection{
		ArchiveID:            archive.Manifest.ArchiveID,
		Version:              archive.State.Version,
		ThresholdBytes:       archive.Manifest.ThresholdBytes,
		TotalPlaintextBytes:  archive.Manifest.TotalPlaintextBytes,
		RemainingPlaintext:   archive.State.RemainingPlaintext,
		ChunkSizeBytes:       archive.Manifest.ChunkSizeBytes,
		TotalChunks:          len(archive.Manifest.Chunks),
		RemainingChunks:      len(archive.State.RemainingChunkIDs),
		DestroyedChunkIDs:    destroyed,
		RemainingChunkIDs:    append([]string(nil), archive.State.RemainingChunkIDs...),
		Decryptable:          archive.State.RemainingPlaintext <= archive.Manifest.ThresholdBytes,
		CurrentRoot:          archive.State.CurrentRoot,
		TrustedStoreVerified: verified,
	}, nil
}

func PruneArchive(opts PruneOptions) (*Archive, error) {
	archive, err := loadArchive(opts.ArchivePath)
	if err != nil {
		return nil, err
	}

	mode, err := normalizeMode(opts.Mode)
	if err != nil {
		return nil, err
	}
	storePath := trustedStorePathFor(opts.ArchivePath, opts.TrustedStorePath)
	if mode == StrongMode {
		if err := verifyTrustedState(storePath, archive); err != nil {
			return nil, err
		}
	}

	keepSet, err := resolveKeepSet(archive, opts.Keep)
	if err != nil {
		return nil, err
	}
	keepBytes := int64(0)
	for _, chunk := range archive.Manifest.Chunks {
		if keepSet[chunk.ID] {
			if chunk.Destroyed {
				return nil, fmt.Errorf("cannot keep destroyed chunk %s", chunk.ID)
			}
			keepBytes += int64(chunk.PlaintextSize)
		}
	}
	if keepBytes > archive.Manifest.ThresholdBytes {
		return nil, errThresholdExceeded
	}

	archive.State.Version++
	archive.State.RemainingChunkIDs = archive.State.RemainingChunkIDs[:0]
	archive.State.RemainingPlaintext = 0

	for i := range archive.Manifest.Chunks {
		chunkMeta := &archive.Manifest.Chunks[i]
		capsule := &archive.Capsules[i]
		if keepSet[chunkMeta.ID] {
			chunkMeta.Destroyed = false
			capsule.Destroyed = false
			archive.State.RemainingChunkIDs = append(archive.State.RemainingChunkIDs, chunkMeta.ID)
			archive.State.RemainingPlaintext += int64(chunkMeta.PlaintextSize)
			capsuleNonce, capsuleCiphertext, err := capsuleBytes(*capsule)
			if err != nil {
				return nil, err
			}
			chunkMeta.CapsuleHash = hashBlob(capsuleNonce, capsuleCiphertext)
			continue
		}
		chunkMeta.Destroyed = true
		capsule.Destroyed = true
		capsule.NonceBase64 = ""
		capsule.Ciphertext = ""
		chunkMeta.CapsuleHash = hashBlob(nil, nil)
	}

	archive.Manifest.ManifestHash = computeManifestHash(archive.Manifest)
	archive.State.CurrentRoot = computeStateRoot(archive.State, archive.Manifest)

	if mode == StrongMode {
		if err := updateTrustedStore(storePath, archive.Manifest.ArchiveID, archive.State.Version, archive.State.CurrentRoot, "", false); err != nil {
			return nil, err
		}
	}
	if err := writeArchive(opts.ArchivePath, archive); err != nil {
		return nil, err
	}
	return archive, nil
}

func DecryptArchive(opts DecryptOptions) ([]byte, error) {
	archive, err := loadArchive(opts.ArchivePath)
	if err != nil {
		return nil, err
	}
	mode, err := normalizeMode(opts.Mode)
	if err != nil {
		return nil, err
	}
	if mode == StrongMode {
		if err := verifyTrustedState(trustedStorePathFor(opts.ArchivePath, opts.TrustedStorePath), archive); err != nil {
			return nil, err
		}
	}
	if archive.State.RemainingPlaintext > archive.Manifest.ThresholdBytes {
		return nil, errThresholdExceeded
	}

	wrapKey, err := decryptWrapKey(opts, archive, mode)
	if err != nil {
		return nil, err
	}

	var output bytes.Buffer
	for i := range archive.Manifest.Chunks {
		if archive.Manifest.Chunks[i].Destroyed {
			continue
		}
		plaintext, err := decryptChunkAt(archive, wrapKey, i)
		if err != nil {
			return nil, err
		}
		output.Write(plaintext)
	}

	if opts.OutputPath != "" {
		if err := os.WriteFile(opts.OutputPath, output.Bytes(), 0o600); err != nil {
			return nil, fmt.Errorf("write decrypted output: %w", err)
		}
	}
	return output.Bytes(), nil
}

func loadArchive(path string) (*Archive, error) {
	if path == "" {
		return nil, errors.New("archive path is required")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read archive: %w", err)
	}
	var archive Archive
	if err := json.Unmarshal(data, &archive); err != nil {
		return nil, fmt.Errorf("parse archive: %w", err)
	}
	if err := validateArchive(&archive); err != nil {
		return nil, err
	}
	return &archive, nil
}

func writeArchive(path string, archive *Archive) error {
	data, err := json.MarshalIndent(archive, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal archive: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write archive: %w", err)
	}
	return nil
}

func validateArchive(archive *Archive) error {
	if archive.Format != archiveFormat {
		return fmt.Errorf("unsupported archive format %q", archive.Format)
	}
	if archive.Manifest.ArchiveID == "" {
		return errors.New("manifest archive_id is required")
	}
	if archive.Manifest.ArchiveID != archive.State.ArchiveID {
		return errors.New("manifest/state archive_id mismatch")
	}
	if archive.Manifest.ThresholdBytes != archive.State.ThresholdBytes {
		return errors.New("manifest/state threshold mismatch")
	}
	if len(archive.Manifest.Chunks) != len(archive.Chunks) || len(archive.Manifest.Chunks) != len(archive.Capsules) {
		return errors.New("manifest/chunks/capsules length mismatch")
	}
	if archive.Manifest.ManifestHash != computeManifestHash(archive.Manifest) {
		return errors.New("manifest hash mismatch")
	}

	remaining := make([]string, 0, len(archive.Manifest.Chunks))
	remainingBytes := int64(0)
	for i, meta := range archive.Manifest.Chunks {
		chunk := archive.Chunks[i]
		capsule := archive.Capsules[i]
		if meta.ID != chunk.ID || meta.ID != capsule.ChunkID {
			return fmt.Errorf("chunk ID mismatch at index %d", i)
		}
		chunkNonce, chunkCiphertext, err := chunkBytes(chunk)
		if err != nil {
			return err
		}
		if meta.CiphertextSize != len(chunkCiphertext) {
			return fmt.Errorf("chunk %s ciphertext size mismatch", meta.ID)
		}
		if meta.CiphertextHash != hashBlob(chunkNonce, chunkCiphertext) {
			return fmt.Errorf("chunk %s ciphertext hash mismatch", meta.ID)
		}
		capsuleNonce, capsuleCiphertext, err := capsuleBytes(capsule)
		if err != nil {
			return err
		}
		if capsule.Destroyed != meta.Destroyed {
			return fmt.Errorf("chunk %s destroyed flag mismatch", meta.ID)
		}
		if meta.CapsuleHash != hashBlob(capsuleNonce, capsuleCiphertext) {
			return fmt.Errorf("chunk %s capsule hash mismatch", meta.ID)
		}
		if meta.Destroyed {
			if capsule.NonceBase64 != "" || capsule.Ciphertext != "" {
				return fmt.Errorf("destroyed capsule %s still contains data", meta.ID)
			}
			continue
		}
		remaining = append(remaining, meta.ID)
		remainingBytes += int64(meta.PlaintextSize)
	}

	if !slices.Equal(remaining, archive.State.RemainingChunkIDs) {
		return errors.New("state remaining chunk IDs mismatch")
	}
	if remainingBytes != archive.State.RemainingPlaintext {
		return errors.New("state remaining plaintext mismatch")
	}
	if archive.State.CurrentRoot != computeStateRoot(archive.State, archive.Manifest) {
		return errors.New("state root mismatch")
	}
	if archive.State.CapsuleWrapKeyBase64 != "" {
		if _, err := decodeBase64URL(archive.State.CapsuleWrapKeyBase64); err != nil {
			return fmt.Errorf("decode capsule wrap key: %w", err)
		}
	}
	return nil
}

func decryptWrapKey(opts DecryptOptions, archive *Archive, mode Mode) ([]byte, error) {
	if mode == StrongMode {
		return trustedWrapKey(trustedStorePathFor(opts.ArchivePath, opts.TrustedStorePath), archive)
	}
	if archive.State.CapsuleWrapKeyBase64 == "" {
		return nil, errors.New("archive is missing capsule wrap key")
	}
	wrapKey, err := decodeBase64URL(archive.State.CapsuleWrapKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("decode capsule wrap key: %w", err)
	}
	return wrapKey, nil
}

func decryptChunkAt(archive *Archive, wrapKey []byte, index int) ([]byte, error) {
	meta := archive.Manifest.Chunks[index]
	if meta.Destroyed {
		return nil, fmt.Errorf("%w: %s", errDestroyedCapsule, meta.ID)
	}
	capsule := archive.Capsules[index]
	capsuleNonce, capsuleCiphertext, err := capsuleBytes(capsule)
	if err != nil {
		return nil, err
	}
	chunkKey, err := openAESGCM(wrapKey, capsuleNonce, capsuleCiphertext, mustJSON(capsuleAAD{
		Type:      "capsule",
		ArchiveID: archive.Manifest.ArchiveID,
		ChunkID:   meta.ID,
	}))
	if err != nil {
		return nil, fmt.Errorf("open capsule %s: %w", meta.ID, err)
	}
	chunk := archive.Chunks[index]
	chunkNonce, chunkCiphertext, err := chunkBytes(chunk)
	if err != nil {
		return nil, err
	}
	plaintext, err := openAESGCM(chunkKey, chunkNonce, chunkCiphertext, mustJSON(chunkAAD{
		Type:          "chunk",
		ArchiveID:     archive.Manifest.ArchiveID,
		ChunkID:       meta.ID,
		Index:         meta.Index,
		PlaintextSize: meta.PlaintextSize,
	}))
	if err != nil {
		return nil, fmt.Errorf("open chunk %s: %w", meta.ID, err)
	}
	return plaintext, nil
}

func resolveKeepSet(archive *Archive, keep []string) (map[string]bool, error) {
	set := make(map[string]bool, len(keep))
	known := make(map[string]ChunkManifest, len(archive.Manifest.Chunks))
	byIndex := make(map[int]string, len(archive.Manifest.Chunks))
	for _, chunk := range archive.Manifest.Chunks {
		known[chunk.ID] = chunk
		byIndex[chunk.Index] = chunk.ID
	}
	for _, item := range keep {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if chunk, ok := known[item]; ok {
			if chunk.Destroyed {
				return nil, fmt.Errorf("chunk %s is already destroyed", item)
			}
			set[item] = true
			continue
		}
		index, err := strconv.Atoi(item)
		if err != nil {
			return nil, fmt.Errorf("unknown chunk %q", item)
		}
		id, ok := byIndex[index]
		if !ok {
			return nil, fmt.Errorf("unknown chunk index %d", index)
		}
		if known[id].Destroyed {
			return nil, fmt.Errorf("chunk %s is already destroyed", id)
		}
		set[id] = true
	}
	return set, nil
}

type chunkAAD struct {
	Type          string `json:"type"`
	ArchiveID     string `json:"archive_id"`
	ChunkID       string `json:"chunk_id"`
	Index         int    `json:"index"`
	PlaintextSize int    `json:"plaintext_size"`
}

type capsuleAAD struct {
	Type      string `json:"type"`
	ArchiveID string `json:"archive_id"`
	ChunkID   string `json:"chunk_id"`
}

func sealAESGCM(key, nonce, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, aad), nil
}

func openAESGCM(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, ciphertext, aad)
}

func computeManifestHash(manifest Manifest) string {
	copy := manifest
	copy.ManifestHash = ""
	return hashJSON(copy)
}

func computeStateRoot(state ArchiveState, manifest Manifest) string {
	material := struct {
		ArchiveID          string   `json:"archive_id"`
		Version            uint64   `json:"version"`
		RemainingChunkIDs  []string `json:"remaining_chunk_ids"`
		RemainingPlaintext int64    `json:"remaining_plaintext_bytes"`
		ThresholdBytes     int64    `json:"threshold_bytes"`
		ManifestHash       string   `json:"manifest_hash"`
	}{
		ArchiveID:          state.ArchiveID,
		Version:            state.Version,
		RemainingChunkIDs:  append([]string(nil), state.RemainingChunkIDs...),
		RemainingPlaintext: state.RemainingPlaintext,
		ThresholdBytes:     state.ThresholdBytes,
		ManifestHash:       manifest.ManifestHash,
	}
	return hashJSON(material)
}

func hashJSON(v any) string {
	return hashBytes(mustJSON(v))
}

func hashBlob(parts ...[]byte) string {
	hash := sha256.New()
	for _, part := range parts {
		hash.Write(part)
	}
	return encodeBase64URL(hash.Sum(nil))
}

func hashBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return encodeBase64URL(sum[:])
}

func trustedStorePathFor(archivePath, explicit string) string {
	if explicit != "" {
		return explicit
	}
	return filepath.Join(filepath.Dir(archivePath), ".bship-trusted.json")
}

func normalizeMode(mode Mode) (Mode, error) {
	switch Mode(strings.TrimSpace(strings.ToLower(string(mode)))) {
	case "", WeakMode:
		return WeakMode, nil
	case StrongMode, StrongModeAlias:
		return StrongMode, nil
	default:
		return "", fmt.Errorf("unsupported mode %q (use %q or %q; %q remains a compatibility alias for the trusted-store simulator)", mode, WeakMode, StrongMode, StrongModeAlias)
	}
}

func encodeBase64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func decodeBase64URL(text string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(text)
}

func chunkBytes(chunk StoredChunk) ([]byte, []byte, error) {
	nonce, err := decodeBase64URL(chunk.NonceBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("decode chunk nonce %s: %w", chunk.ID, err)
	}
	ciphertext, err := decodeBase64URL(chunk.Ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("decode chunk ciphertext %s: %w", chunk.ID, err)
	}
	return nonce, ciphertext, nil
}

func capsuleBytes(capsule Capsule) ([]byte, []byte, error) {
	if capsule.Destroyed {
		if capsule.NonceBase64 != "" || capsule.Ciphertext != "" {
			return nil, nil, fmt.Errorf("destroyed capsule %s must be empty", capsule.ChunkID)
		}
		return nil, nil, nil
	}
	nonce, err := decodeBase64URL(capsule.NonceBase64)
	if err != nil {
		return nil, nil, fmt.Errorf("decode capsule nonce %s: %w", capsule.ChunkID, err)
	}
	ciphertext, err := decodeBase64URL(capsule.Ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("decode capsule ciphertext %s: %w", capsule.ChunkID, err)
	}
	return nonce, ciphertext, nil
}

func randomArchiveID(r io.Reader) (string, error) {
	buf, err := randomBytes(r, 16)
	if err != nil {
		return "", fmt.Errorf("generate archive ID: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func randomBytes(r io.Reader, size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func mustJSON(v any) []byte {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return data
}
