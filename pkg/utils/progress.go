package utils

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// ProgressBar represents a progress bar
type ProgressBar struct {
	total     int
	current   int
	width     int
	prefix    string
	suffix    string
	mu        sync.Mutex
	startTime time.Time
	lastUpdate time.Time
}

// NewProgressBar creates a new progress bar
func NewProgressBar(total int, prefix string) *ProgressBar {
	return &ProgressBar{
		total:      total,
		current:    0,
		width:      40,
		prefix:     prefix,
		startTime:  time.Now(),
		lastUpdate: time.Now(),
	}
}

// Update updates the progress bar
func (pb *ProgressBar) Update(current int) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	pb.current = current
	if pb.current > pb.total {
		pb.current = pb.total
	}

	// Rate limit updates to avoid flickering
	if time.Since(pb.lastUpdate) < 100*time.Millisecond && current < pb.total {
		return
	}
	pb.lastUpdate = time.Now()

	pb.render()
}

// Increment increments the progress bar by 1
func (pb *ProgressBar) Increment() {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	pb.current++
	if pb.current > pb.total {
		pb.current = pb.total
	}

	// Rate limit updates
	if time.Since(pb.lastUpdate) < 100*time.Millisecond && pb.current < pb.total {
		return
	}
	pb.lastUpdate = time.Now()

	pb.render()
}

// SetTotal sets the total count
func (pb *ProgressBar) SetTotal(total int) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	pb.total = total
}

// SetSuffix sets the suffix text
func (pb *ProgressBar) SetSuffix(suffix string) {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	pb.suffix = suffix
}

// Finish completes the progress bar
func (pb *ProgressBar) Finish() {
	pb.mu.Lock()
	defer pb.mu.Unlock()

	pb.current = pb.total
	pb.render()
	fmt.Println()
}

// render renders the progress bar
func (pb *ProgressBar) render() {
	if pb.total == 0 {
		return
	}

	percent := float64(pb.current) / float64(pb.total)
	filled := int(float64(pb.width) * percent)
	empty := pb.width - filled

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)

	elapsed := time.Since(pb.startTime)
	remaining := time.Duration(0)
	if pb.current > 0 {
		remaining = time.Duration(float64(elapsed) / float64(pb.current) * float64(pb.total-pb.current))
	}

	suffix := pb.suffix
	if suffix == "" {
		suffix = fmt.Sprintf("%d/%d", pb.current, pb.total)
	}

	fmt.Printf("\r%s [%s] %.1f%% %s ETA: %s",
		pb.prefix,
		bar,
		percent*100,
		suffix,
		formatDuration(remaining),
	)
}

// formatDuration formats a duration as HH:MM:SS
func formatDuration(d time.Duration) string {
	if d < 0 {
		return "00:00:00"
	}

	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	return fmt.Sprintf("%02d:%02d:%02d", hours, minutes, seconds)
}

// Spinner represents a spinner animation
type Spinner struct {
	frames  []string
	message string
	current int
	mu      sync.Mutex
	done    chan struct{}
	running bool
}

// NewSpinner creates a new spinner
func NewSpinner(message string) *Spinner {
	return &Spinner{
		frames:  []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		message: message,
		done:    make(chan struct{}),
	}
}

// Start starts the spinner animation
func (s *Spinner) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	go func() {
		for {
			select {
			case <-s.done:
				return
			default:
				s.mu.Lock()
				frame := s.frames[s.current%len(s.frames)]
				s.current++
				fmt.Printf("\r%s %s", frame, s.message)
				s.mu.Unlock()
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
}

// Stop stops the spinner animation
func (s *Spinner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	s.running = false
	close(s.done)
	fmt.Printf("\r%s ✓\n", s.message)
}

// UpdateMessage updates the spinner message
func (s *Spinner) UpdateMessage(message string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.message = message
}
