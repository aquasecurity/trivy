// +build !windows

package wait

import "syscall"

func isConnRefusedErr(err error) bool {
	return err == syscall.ECONNREFUSED
}
