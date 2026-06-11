package sources

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/h2non/filetype"

	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/logging"
)

const defaultBufferSize = 100 * 1_000 // 100kb
const InnerPathSeparator = "!"

// File is a source for yielding fragments from a file or other reader
type File struct {
	// Content provides a reader to the file's content
	Content io.Reader
	// Path is the resolved real path of the file
	Path string
	// Symlink represents a symlink to the file if that's how it was discovered
	Symlink string
	// Buffer is used for reading the content in chunks
	Buffer []byte
	// Config is the gitleaks config used for shouldSkipPath. If not set, then
	// shouldSkipPath is ignored
	Config *config.Config
	// outerPaths is the list of container paths (e.g. archives) that lead to
	// this file
	outerPaths []string
	// MaxArchiveDepth is retained for API compatibility but archive scanning is
	// disabled in this build (no-archives stub). The field is not read.
	MaxArchiveDepth int
	// archiveDepth is the current archive nesting depth
	archiveDepth int
}

// Fragments yields fragments for this source.
// Archive extraction is stubbed out: every file is treated as a plain file.
func (s *File) Fragments(ctx context.Context, yield FragmentsFunc) error {
	return s.fileFragments(ctx, bufio.NewReader(s.Content), yield)
}

// fileFragments reads the file into fragments to yield
func (s *File) fileFragments(ctx context.Context, reader *bufio.Reader, yield FragmentsFunc) error {
	// Create a buffer if the caller hasn't provided one
	if s.Buffer == nil {
		s.Buffer = make([]byte, defaultBufferSize)
	}

	totalLines := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			fragment := Fragment{
				FilePath: s.FullPath(),
			}

			n, err := reader.Read(s.Buffer)
			if n == 0 {
				if err != nil && err != io.EOF {
					return yield(fragment, fmt.Errorf("could not read file: %w", err))
				}

				return nil
			}

			// Only check the filetype at the start of file.
			if totalLines == 0 {
				// TODO: could other optimizations be introduced here?
				if mimetype, err := filetype.Match(s.Buffer[:n]); err != nil {
					return yield(
						fragment,
						fmt.Errorf("could not read file: could not determine type: %w", err),
					)
				} else if mimetype.MIME.Type == "application" {
					logging.Debug().
						Str("mime_type", mimetype.MIME.Value).
						Str("path", s.FullPath()).
						Msgf("skipping binary file")

					return nil
				}
			}

			// Try to split chunks across large areas of whitespace, if possible.
			peekBuf := bytes.NewBuffer(s.Buffer[:n])
			if err := readUntilSafeBoundary(reader, n, maxPeekSize, peekBuf); err != nil {
				return yield(
					fragment,
					fmt.Errorf("could not read file: could not read until safe boundary: %w", err),
				)
			}

			fragment.Raw = peekBuf.String()
			fragment.Bytes = peekBuf.Bytes()
			fragment.StartLine = totalLines + 1

			// Count the number of newlines in this chunk
			totalLines += strings.Count(fragment.Raw, "\n")

			if len(s.Symlink) > 0 {
				fragment.SymlinkFile = s.Symlink
			}

			if isWindows {
				fragment.FilePath = filepath.ToSlash(fragment.FilePath)
				fragment.SymlinkFile = filepath.ToSlash(s.Symlink)
				fragment.WindowsFilePath = s.FullPath()
			}

			// log errors but continue since there's content
			if err != nil && err != io.EOF {
				logging.Warn().Err(err).Msgf("issue reading file")
			}

			// Done with the file!
			if err == io.EOF {
				return yield(fragment, nil)
			}

			if err := yield(fragment, err); err != nil {
				return err
			}
		}
	}
}

// FullPath returns the File.Path with any preceding outer paths
func (s *File) FullPath() string {
	if len(s.outerPaths) > 0 {
		return strings.Join(
			// outerPaths have already been normalized to slash
			append(s.outerPaths, s.Path),
			InnerPathSeparator,
		)
	}

	return s.Path
}
