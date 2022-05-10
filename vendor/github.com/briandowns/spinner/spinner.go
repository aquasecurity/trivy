// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package spinner is a simple package to add a spinner / progress indicator to any terminal application.
package spinner

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/fatih/color"
)

// errInvalidColor is returned when attempting to set an invalid color
var errInvalidColor = errors.New("invalid color")

// validColors holds an array of the only colors allowed
var validColors = map[string]bool{
	// default colors for backwards compatibility
	"black":   true,
	"red":     true,
	"green":   true,
	"yellow":  true,
	"blue":    true,
	"magenta": true,
	"cyan":    true,
	"white":   true,

	// attributes
	"reset":        true,
	"bold":         true,
	"faint":        true,
	"italic":       true,
	"underline":    true,
	"blinkslow":    true,
	"blinkrapid":   true,
	"reversevideo": true,
	"concealed":    true,
	"crossedout":   true,

	// foreground text
	"fgBlack":   true,
	"fgRed":     true,
	"fgGreen":   true,
	"fgYellow":  true,
	"fgBlue":    true,
	"fgMagenta": true,
	"fgCyan":    true,
	"fgWhite":   true,

	// foreground Hi-Intensity text
	"fgHiBlack":   true,
	"fgHiRed":     true,
	"fgHiGreen":   true,
	"fgHiYellow":  true,
	"fgHiBlue":    true,
	"fgHiMagenta": true,
	"fgHiCyan":    true,
	"fgHiWhite":   true,

	// background text
	"bgBlack":   true,
	"bgRed":     true,
	"bgGreen":   true,
	"bgYellow":  true,
	"bgBlue":    true,
	"bgMagenta": true,
	"bgCyan":    true,
	"bgWhite":   true,

	// background Hi-Intensity text
	"bgHiBlack":   true,
	"bgHiRed":     true,
	"bgHiGreen":   true,
	"bgHiYellow":  true,
	"bgHiBlue":    true,
	"bgHiMagenta": true,
	"bgHiCyan":    true,
	"bgHiWhite":   true,
}

// returns a valid color's foreground text color attribute
var colorAttributeMap = map[string]color.Attribute{
	// default colors for backwards compatibility
	"black":   color.FgBlack,
	"red":     color.FgRed,
	"green":   color.FgGreen,
	"yellow":  color.FgYellow,
	"blue":    color.FgBlue,
	"magenta": color.FgMagenta,
	"cyan":    color.FgCyan,
	"white":   color.FgWhite,

	// attributes
	"reset":        color.Reset,
	"bold":         color.Bold,
	"faint":        color.Faint,
	"italic":       color.Italic,
	"underline":    color.Underline,
	"blinkslow":    color.BlinkSlow,
	"blinkrapid":   color.BlinkRapid,
	"reversevideo": color.ReverseVideo,
	"concealed":    color.Concealed,
	"crossedout":   color.CrossedOut,

	// foreground text colors
	"fgBlack":   color.FgBlack,
	"fgRed":     color.FgRed,
	"fgGreen":   color.FgGreen,
	"fgYellow":  color.FgYellow,
	"fgBlue":    color.FgBlue,
	"fgMagenta": color.FgMagenta,
	"fgCyan":    color.FgCyan,
	"fgWhite":   color.FgWhite,

	// foreground Hi-Intensity text colors
	"fgHiBlack":   color.FgHiBlack,
	"fgHiRed":     color.FgHiRed,
	"fgHiGreen":   color.FgHiGreen,
	"fgHiYellow":  color.FgHiYellow,
	"fgHiBlue":    color.FgHiBlue,
	"fgHiMagenta": color.FgHiMagenta,
	"fgHiCyan":    color.FgHiCyan,
	"fgHiWhite":   color.FgHiWhite,

	// background text colors
	"bgBlack":   color.BgBlack,
	"bgRed":     color.BgRed,
	"bgGreen":   color.BgGreen,
	"bgYellow":  color.BgYellow,
	"bgBlue":    color.BgBlue,
	"bgMagenta": color.BgMagenta,
	"bgCyan":    color.BgCyan,
	"bgWhite":   color.BgWhite,

	// background Hi-Intensity text colors
	"bgHiBlack":   color.BgHiBlack,
	"bgHiRed":     color.BgHiRed,
	"bgHiGreen":   color.BgHiGreen,
	"bgHiYellow":  color.BgHiYellow,
	"bgHiBlue":    color.BgHiBlue,
	"bgHiMagenta": color.BgHiMagenta,
	"bgHiCyan":    color.BgHiCyan,
	"bgHiWhite":   color.BgHiWhite,
}

// validColor will make sure the given color is actually allowed.
func validColor(c string) bool {
	if validColors[c] {
		return true
	}
	return false
}

// Spinner struct to hold the provided options.
type Spinner struct {
	mu         *sync.RWMutex                 //
	Delay      time.Duration                 // Delay is the speed of the indicator
	chars      []string                      // chars holds the chosen character set
	Prefix     string                        // Prefix is the text preppended to the indicator
	Suffix     string                        // Suffix is the text appended to the indicator
	FinalMSG   string                        // string displayed after Stop() is called
	lastOutput string                        // last character(set) written
	color      func(a ...interface{}) string // default color is white
	Writer     io.Writer                     // to make testing better, exported so users have access. Use `WithWriter` to update after initialization.
	active     bool                          // active holds the state of the spinner
	stopChan   chan struct{}                 // stopChan is a channel used to stop the indicator
	HideCursor bool                          // hideCursor determines if the cursor is visible
	PreUpdate  func(s *Spinner)              // will be triggered before every spinner update
	PostUpdate func(s *Spinner)              // will be triggered after every spinner update
}

// New provides a pointer to an instance of Spinner with the supplied options.
func New(cs []string, d time.Duration, options ...Option) *Spinner {
	s := &Spinner{
		Delay:    d,
		chars:    cs,
		color:    color.New(color.FgWhite).SprintFunc(),
		mu:       &sync.RWMutex{},
		Writer:   color.Output,
		active:   false,
		stopChan: make(chan struct{}, 1),
	}

	for _, option := range options {
		option(s)
	}
	return s
}

// Option is a function that takes a spinner and applies
// a given configuration.
type Option func(*Spinner)

// Options contains fields to configure the spinner.
type Options struct {
	Color      string
	Suffix     string
	FinalMSG   string
	HideCursor bool
}

// WithColor adds the given color to the spinner.
func WithColor(color string) Option {
	return func(s *Spinner) {
		s.Color(color)
	}
}

// WithSuffix adds the given string to the spinner
// as the suffix.
func WithSuffix(suffix string) Option {
	return func(s *Spinner) {
		s.Suffix = suffix
	}
}

// WithFinalMSG adds the given string ot the spinner
// as the final message to be written.
func WithFinalMSG(finalMsg string) Option {
	return func(s *Spinner) {
		s.FinalMSG = finalMsg
	}
}

// WithHiddenCursor hides the cursor
// if hideCursor = true given.
func WithHiddenCursor(hideCursor bool) Option {
	return func(s *Spinner) {
		s.HideCursor = hideCursor
	}
}

// WithWriter adds the given writer to the spinner. This
// function should be favored over directly assigning to
// the struct value.
func WithWriter(w io.Writer) Option {
	return func(s *Spinner) {
		s.mu.Lock()
		s.Writer = w
		s.mu.Unlock()
	}
}

// Active will return whether or not the spinner is currently active.
func (s *Spinner) Active() bool {
	return s.active
}

// Start will start the indicator.
func (s *Spinner) Start() {
	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		return
	}
	if s.HideCursor && runtime.GOOS != "windows" {
		// hides the cursor
		fmt.Print("\033[?25l")
	}
	s.active = true
	s.mu.Unlock()

	go func() {
		for {
			for i := 0; i < len(s.chars); i++ {
				select {
				case <-s.stopChan:
					return
				default:
					s.mu.Lock()
					if !s.active {
						s.mu.Unlock()
						return
					}
					s.erase()

					if s.PreUpdate != nil {
						s.PreUpdate(s)
					}

					var outColor string
					if runtime.GOOS == "windows" {
						if s.Writer == os.Stderr {
							outColor = fmt.Sprintf("\r%s%s%s ", s.Prefix, s.chars[i], s.Suffix)
						} else {
							outColor = fmt.Sprintf("\r%s%s%s ", s.Prefix, s.color(s.chars[i]), s.Suffix)
						}
					} else {
						outColor = fmt.Sprintf("\r%s%s%s ", s.Prefix, s.color(s.chars[i]), s.Suffix)
					}
					outPlain := fmt.Sprintf("\r%s%s%s ", s.Prefix, s.chars[i], s.Suffix)
					fmt.Fprint(s.Writer, outColor)
					s.lastOutput = outPlain
					delay := s.Delay

					if s.PostUpdate != nil {
						s.PostUpdate(s)
					}

					s.mu.Unlock()
					time.Sleep(delay)
				}
			}
		}
	}()
}

// Stop stops the indicator.
func (s *Spinner) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		s.active = false
		if s.HideCursor && runtime.GOOS != "windows" {
			// makes the cursor visible
			fmt.Print("\033[?25h")
		}
		s.erase()
		if s.FinalMSG != "" {
			fmt.Fprint(s.Writer, s.FinalMSG)
		}
		s.stopChan <- struct{}{}
	}
}

// Restart will stop and start the indicator.
func (s *Spinner) Restart() {
	s.Stop()
	s.Start()
}

// Reverse will reverse the order of the slice assigned to the indicator.
func (s *Spinner) Reverse() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, j := 0, len(s.chars)-1; i < j; i, j = i+1, j-1 {
		s.chars[i], s.chars[j] = s.chars[j], s.chars[i]
	}
}

// Color will set the struct field for the given color to be used. The spinner
// will need to be explicitly restarted.
func (s *Spinner) Color(colors ...string) error {
	colorAttributes := make([]color.Attribute, len(colors))

	// Verify colours are valid and place the appropriate attribute in the array
	for index, c := range colors {
		if !validColor(c) {
			return errInvalidColor
		}
		colorAttributes[index] = colorAttributeMap[c]
	}

	s.mu.Lock()
	s.color = color.New(colorAttributes...).SprintFunc()
	s.mu.Unlock()
	return nil
}

// UpdateSpeed will set the indicator delay to the given value.
func (s *Spinner) UpdateSpeed(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Delay = d
}

// UpdateCharSet will change the current character set to the given one.
func (s *Spinner) UpdateCharSet(cs []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.chars = cs
}

// erase deletes written characters.
// Caller must already hold s.lock.
func (s *Spinner) erase() {
	n := utf8.RuneCountInString(s.lastOutput)
	if runtime.GOOS == "windows" {
		clearString := "\r" + strings.Repeat(" ", n) + "\r"
		fmt.Fprint(s.Writer, clearString)
		s.lastOutput = ""
		return
	}
	for _, c := range []string{"\b", "\127", "\b", "\033[K"} { // "\033[K" for macOS Terminal
		fmt.Fprint(s.Writer, strings.Repeat(c, n))
	}
	fmt.Fprintf(s.Writer, "\r\033[K") // erases to end of line
	s.lastOutput = ""
}

// Lock allows for manual control to lock the spinner.
func (s *Spinner) Lock() {
	s.mu.Lock()
}

// Unlock allows for manual control to unlock the spinner.
func (s *Spinner) Unlock() {
	s.mu.Unlock()
}

// GenerateNumberSequence will generate a slice of integers at the
// provided length and convert them each to a string.
func GenerateNumberSequence(length int) []string {
	numSeq := make([]string, length)
	for i := 0; i < length; i++ {
		numSeq[i] = strconv.Itoa(i)
	}
	return numSeq
}
