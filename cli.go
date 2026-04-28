package bship

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
)

const (
	modeFlagHelp         = "mode to use: weak (default) or simulated-strong; \"strong\" remains a compatibility alias for the simulator-backed mode"
	trustedStoreFlagHelp = "path to local JSON trusted-store simulator state for simulated-strong/strong; this file is demo/test state, not a secure trusted component"
)

func RunCLI(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "seal":
		return runSeal(args[1:], stdout, stderr)
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "prune":
		return runPrune(args[1:], stdout, stderr)
	case "decrypt":
		return runDecrypt(args[1:], stdout, stderr)
	case "-h", "--help", "help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runSeal(args []string, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("seal", "Seal a file into a BottleShip archive.", stderr)
	inPath := fs.String("in", "", "input file to seal")
	outPath := fs.String("out", "", "output .bship archive")
	threshold := fs.Int64("threshold", 0, "maximum decryptable plaintext bytes")
	chunkSize := fs.Int("chunk-size", 1024, "plaintext chunk size in bytes")
	modeValue := fs.String("mode", string(WeakMode), modeFlagHelp)
	storePath := fs.String("trusted-store", "", trustedStoreFlagHelp)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	mode, err := parseCLIMode(*modeValue)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	archive, err := SealFile(SealOptions{
		InputPath:        *inPath,
		ArchivePath:      *outPath,
		ThresholdBytes:   *threshold,
		ChunkSizeBytes:   *chunkSize,
		Mode:             mode,
		TrustedStorePath: *storePath,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "sealed %s (%d chunks, version %d)\n", archive.Manifest.ArchiveID, len(archive.Manifest.Chunks), archive.State.Version)
	return 0
}

func runInspect(args []string, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("inspect", "Inspect archive state without decrypting.", stderr)
	archivePath := fs.String("archive", "", "archive to inspect")
	modeValue := fs.String("mode", string(WeakMode), modeFlagHelp)
	storePath := fs.String("trusted-store", "", trustedStoreFlagHelp)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	mode, err := parseCLIMode(*modeValue)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	inspection, err := InspectArchive(InspectOptions{
		ArchivePath:      *archivePath,
		Mode:             mode,
		TrustedStorePath: *storePath,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	data, err := json.MarshalIndent(inspection, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "%s\n", data)
	return 0
}

func runPrune(args []string, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("prune", "Destroy selected chunk capsules to reduce decryptable plaintext.", stderr)
	archivePath := fs.String("archive", "", "archive to prune")
	keepValue := fs.String("keep", "", "comma-separated chunk IDs or indices to keep")
	modeValue := fs.String("mode", string(WeakMode), modeFlagHelp)
	storePath := fs.String("trusted-store", "", trustedStoreFlagHelp)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	mode, err := parseCLIMode(*modeValue)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	archive, err := PruneArchive(PruneOptions{
		ArchivePath:      *archivePath,
		Keep:             splitCSV(*keepValue),
		Mode:             mode,
		TrustedStorePath: *storePath,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "pruned %s to %d chunks (version %d)\n", archive.Manifest.ArchiveID, len(archive.State.RemainingChunkIDs), archive.State.Version)
	return 0
}

func runDecrypt(args []string, stdout, stderr io.Writer) int {
	fs := newCommandFlagSet("decrypt", "Decrypt the currently recoverable plaintext.", stderr)
	archivePath := fs.String("archive", "", "archive to decrypt")
	outPath := fs.String("out", "", "output file for remaining plaintext")
	modeValue := fs.String("mode", string(WeakMode), modeFlagHelp)
	storePath := fs.String("trusted-store", "", trustedStoreFlagHelp)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	mode, err := parseCLIMode(*modeValue)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	plaintext, err := DecryptArchive(DecryptOptions{
		ArchivePath:      *archivePath,
		OutputPath:       *outPath,
		Mode:             mode,
		TrustedStorePath: *storePath,
	})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stdout, "decrypted %d bytes\n", len(plaintext))
	return 0
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: bship <seal|inspect|prune|decrypt> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Modes:")
	fmt.Fprintf(w, "  %s              archive carries all decryption material in the archive itself.\n", WeakMode)
	fmt.Fprintf(w, "  %s  local JSON trusted-store simulator; %q is accepted as a compatibility alias.\n", StrongMode, StrongModeAlias)
	fmt.Fprintln(w, "                     This simulator state is not a secure trusted component or strong-model security boundary.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, `Use "bship <command> -h" for command-specific flags.`)
}

func newCommandFlagSet(name, description string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: bship %s [flags]\n", name)
		if description != "" {
			fmt.Fprintln(stderr, description)
		}
		fmt.Fprintln(stderr)
		fs.PrintDefaults()
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Mode notes:")
		fmt.Fprintf(stderr, "  %s              archive-only state; copying old archives can bypass pruning.\n", WeakMode)
		fmt.Fprintf(stderr, "  %s  local JSON trusted-store simulator; %q stays supported as an alias.\n", StrongMode, StrongModeAlias)
		fmt.Fprintln(stderr, "                     The trusted-store file is only local simulator state, not secure hardware or a trusted component.")
	}
	return fs
}

func parseCLIMode(value string) (Mode, error) {
	return normalizeMode(Mode(value))
}

func splitCSV(value string) []string {
	if value == "" {
		return nil
	}
	items := strings.Split(value, ",")
	result := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			result = append(result, item)
		}
	}
	return result
}
