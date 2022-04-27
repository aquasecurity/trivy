// Copyright 2017 Google, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Package cmd contains utilities to execute commands using a test-friendly
interface.
*/
package cmd

import (
	"os/exec"
)

// Command execs a command with the given arguments.
type Command interface {
	Exec(...string) ([]byte, error)
}

// RealImpl is a real implementation of Command which uses exec.Command to
// execute the given cmd.
type RealImpl struct {
	// The command to execute.
	Command string
}

// Exec executes the defined command with the given args, returning the results
// of stdout, or an error.
func (s *RealImpl) Exec(args ...string) ([]byte, error) {
	return exec.Command(s.Command, args...).Output()
}
