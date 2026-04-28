package bship

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
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
	fs := flag.NewFlagSet("seal", flag.ContinueOnError)
	fs.SetOutput(stderr)
	inPath := fs.String("in", "", "input file to seal")
	outPath := fs.String("out", "", "output .bship archive")
	threshold := fs.Int64("threshold", 0, "maximum decryptable plaintext bytes")
	chunkSize := fs.Int("chunk-size", 1024, "plaintext chunk size in bytes")
	modeValue := fs.String("mode", string(WeakMode), "weak or strong")
	storePath := fs.String("trusted-store", "", "trusted store path for strong mode")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	archive, err := SealFile(SealOptions{
		InputPath:        *inPath,
		ArchivePath:      *outPath,
		ThresholdBytes:   *threshold,
		ChunkSizeBytes:   *chunkSize,
		Mode:             Mode(*modeValue),
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
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	archivePath := fs.String("archive", "", "archive to inspect")
	modeValue := fs.String("mode", string(WeakMode), "weak or strong")
	storePath := fs.String("trusted-store", "", "trusted store path for strong mode")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	inspection, err := InspectArchive(InspectOptions{
		ArchivePath:      *archivePath,
		Mode:             Mode(*modeValue),
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
	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	fs.SetOutput(stderr)
	archivePath := fs.String("archive", "", "archive to prune")
	keepValue := fs.String("keep", "", "comma-separated chunk IDs or indices to keep")
	modeValue := fs.String("mode", string(WeakMode), "weak or strong")
	storePath := fs.String("trusted-store", "", "trusted store path for strong mode")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	archive, err := PruneArchive(PruneOptions{
		ArchivePath:      *archivePath,
		Keep:             splitCSV(*keepValue),
		Mode:             Mode(*modeValue),
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
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	fs.SetOutput(stderr)
	archivePath := fs.String("archive", "", "archive to decrypt")
	outPath := fs.String("out", "", "output file for remaining plaintext")
	modeValue := fs.String("mode", string(WeakMode), "weak or strong")
	storePath := fs.String("trusted-store", "", "trusted store path for strong mode")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	plaintext, err := DecryptArchive(DecryptOptions{
		ArchivePath:      *archivePath,
		OutputPath:       *outPath,
		Mode:             Mode(*modeValue),
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
