package mediaproc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// Video handling shells out to ffmpeg.
//
// There is no usable pure-Go H.264/H.265 encoder, and writing one is not a
// reasonable thing to do. ffmpeg is in the consumer's image (see
// build/Dockerfile.mediaproc) and is invoked as a subprocess with a hard
// timeout, a memory-bounded working directory and no network access.
//
// The security posture matters here: ffmpeg parses attacker-supplied
// container formats, which is historically where its CVEs live. It runs as a
// non-root user, in a pod with a read-only root filesystem, with every
// capability dropped, on a temporary directory that is deleted afterwards.

// ErrFFmpegMissing is returned when the binary is not on PATH.
var ErrFFmpegMissing = errors.New("mediaproc: ffmpeg is not installed")

// VideoInfo is what ffprobe reports.
type VideoInfo struct {
	Width      int
	Height     int
	DurationMS int64
	Bitrate    int64
	Codec      string
	HasAudio   bool
}

// Transcoder wraps ffmpeg and ffprobe.
type Transcoder struct {
	FFmpegPath  string
	FFprobePath string
	// Timeout bounds one invocation. A long video legitimately takes minutes;
	// a crafted one can make ffmpeg spin forever.
	Timeout time.Duration
	// MaxOutputBytes bounds what a transcode may produce, so a decompression
	// bomb cannot fill the node's disk.
	MaxOutputBytes int64
}

// NewTranscoder locates the binaries.
func NewTranscoder() (*Transcoder, error) {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		return nil, ErrFFmpegMissing
	}
	ffprobe, err := exec.LookPath("ffprobe")
	if err != nil {
		return nil, ErrFFmpegMissing
	}
	return &Transcoder{
		FFmpegPath:     ffmpeg,
		FFprobePath:    ffprobe,
		Timeout:        10 * time.Minute,
		MaxOutputBytes: 2 << 30,
	}, nil
}

type ffprobeOutput struct {
	Streams []struct {
		CodecType string `json:"codec_type"`
		CodecName string `json:"codec_name"`
		Width     int    `json:"width"`
		Height    int    `json:"height"`
	} `json:"streams"`
	Format struct {
		Duration string `json:"duration"`
		BitRate  string `json:"bit_rate"`
	} `json:"format"`
}

// ProbeVideo reads the container metadata without decoding any frames.
func (t *Transcoder) ProbeVideo(ctx context.Context, path string) (VideoInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, t.FFprobePath,
		"-v", "error",
		"-print_format", "json",
		"-show_format",
		"-show_streams",
		path,
	)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return VideoInfo{}, fmt.Errorf("mediaproc: ffprobe: %w: %s", err, trim(stderr.String()))
	}

	var parsed ffprobeOutput
	if err := json.Unmarshal(out.Bytes(), &parsed); err != nil {
		return VideoInfo{}, fmt.Errorf("mediaproc: parse ffprobe output: %w", err)
	}

	info := VideoInfo{}
	for _, s := range parsed.Streams {
		switch s.CodecType {
		case "video":
			if info.Width == 0 {
				info.Width, info.Height, info.Codec = s.Width, s.Height, s.CodecName
			}
		case "audio":
			info.HasAudio = true
		}
	}
	if secs, err := strconv.ParseFloat(parsed.Format.Duration, 64); err == nil {
		info.DurationMS = int64(secs * 1000)
	}
	if br, err := strconv.ParseInt(parsed.Format.BitRate, 10, 64); err == nil {
		info.Bitrate = br
	}
	if info.Width == 0 {
		return info, errors.New("mediaproc: the file contains no video stream")
	}
	return info, nil
}

// VideoThumbnail extracts a single frame as JPEG.
//
// The frame is taken one second in, not at zero: the first frame of a video
// is very often a black or blank fade-in, which makes a useless thumbnail.
func (t *Transcoder) VideoThumbnail(ctx context.Context, path string, maxDim int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	dir, err := os.MkdirTemp("", "thumb-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	outPath := filepath.Join(dir, "frame.jpg")

	cmd := exec.CommandContext(ctx, t.FFmpegPath,
		"-nostdin",
		"-v", "error",
		// -ss before -i seeks by keyframe, which is near-instant. After -i it
		// decodes every frame up to the seek point, which on a long video is
		// the difference between milliseconds and minutes.
		"-ss", "00:00:01",
		"-i", path,
		"-frames:v", "1",
		"-vf", fmt.Sprintf("scale='min(%d,iw)':'min(%d,ih)':force_original_aspect_ratio=decrease", maxDim, maxDim),
		"-q:v", "3",
		"-y", outPath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// A video shorter than a second has no frame at 00:00:01. Retry from
		// the very start rather than declaring the file broken.
		return t.videoThumbnailAt(ctx, path, maxDim, "00:00:00")
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("mediaproc: read extracted frame: %w", err)
	}
	return data, nil
}

func (t *Transcoder) videoThumbnailAt(ctx context.Context, path string, maxDim int, at string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "thumb-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	outPath := filepath.Join(dir, "frame.jpg")

	cmd := exec.CommandContext(ctx, t.FFmpegPath,
		"-nostdin", "-v", "error",
		"-ss", at, "-i", path,
		"-frames:v", "1",
		"-vf", fmt.Sprintf("scale='min(%d,iw)':'min(%d,ih)':force_original_aspect_ratio=decrease", maxDim, maxDim),
		"-q:v", "3", "-y", outPath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("mediaproc: extract frame: %w: %s", err, trim(stderr.String()))
	}
	return os.ReadFile(outPath)
}

// TranscodeProfile describes one output rendition.
type TranscodeProfile struct {
	Name      string
	MaxHeight int
	// CRF is the quality target: lower is better and larger. 23 is ffmpeg's
	// default and visually transparent for most content; 28 is noticeably
	// smaller and acceptable on a phone screen.
	CRF int
	// AudioBitrate in kbps.
	AudioBitrate int
}

// DefaultProfiles are the renditions produced for a video message.
//
// One rendition, not a ladder. Adaptive bitrate streaming is the right answer
// for a video platform; a chat sends a clip that is watched once, and building
// an HLS ladder for it would multiply storage and processing cost for a
// benefit nobody would notice.
var DefaultProfiles = []TranscodeProfile{
	{Name: "_720p", MaxHeight: 720, CRF: 26, AudioBitrate: 96},
}

// Transcode re-encodes a video to H.264/AAC in an MP4 container.
func (t *Transcoder) Transcode(ctx context.Context, srcPath, dstPath string, p TranscodeProfile) error {
	ctx, cancel := context.WithTimeout(ctx, t.Timeout)
	defer cancel()

	crf := p.CRF
	if crf <= 0 {
		crf = 26
	}
	audioBitrate := p.AudioBitrate
	if audioBitrate <= 0 {
		audioBitrate = 96
	}

	cmd := exec.CommandContext(ctx, t.FFmpegPath,
		"-nostdin",
		"-v", "error",
		"-i", srcPath,

		// H.264 baseline-compatible: plays on every device anyone still owns.
		// HEVC would be ~30% smaller and would fail to play on a meaningful
		// share of Android handsets.
		"-c:v", "libx264",
		"-preset", "medium",
		"-crf", strconv.Itoa(crf),
		"-profile:v", "high",
		"-level", "4.0",
		"-pix_fmt", "yuv420p", // some encoders emit 4:4:4, which many decoders refuse

		// Scale down only. Upscaling a 480p clip to 720p adds bytes and no
		// detail. The -2 keeps the width even, which H.264 requires.
		"-vf", fmt.Sprintf("scale=-2:'min(%d,ih)'", p.MaxHeight),

		"-c:a", "aac",
		"-b:a", fmt.Sprintf("%dk", audioBitrate),
		"-ac", "2",

		// faststart moves the index to the front of the file so playback can
		// begin before the whole thing has downloaded. Without it a phone
		// buffers the entire clip before showing a frame.
		"-movflags", "+faststart",

		"-y", dstPath,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("mediaproc: transcode timed out after %s", t.Timeout)
		}
		return fmt.Errorf("mediaproc: transcode: %w: %s", err, trim(stderr.String()))
	}

	st, err := os.Stat(dstPath)
	if err != nil {
		return fmt.Errorf("mediaproc: stat transcoded output: %w", err)
	}
	if t.MaxOutputBytes > 0 && st.Size() > t.MaxOutputBytes {
		_ = os.Remove(dstPath)
		return fmt.Errorf("mediaproc: transcoded output of %d bytes exceeds the limit", st.Size())
	}
	return nil
}

func trim(s string) string {
	const max = 400
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
