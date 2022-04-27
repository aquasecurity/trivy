// +build linux darwin freebsd netbsd openbsd solaris dragonfly
// +build !appengine

package termutil

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var (
	tty *os.File

	unlockSignals = []os.Signal{
		os.Interrupt, syscall.SIGQUIT, syscall.SIGTERM, syscall.SIGKILL,
	}
)

type window struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

func init() {
	var err error
	tty, err = os.Open("/dev/tty")
	if err != nil {
		tty = os.Stdin
	}
}

// TerminalWidth returns width of the terminal.
func TerminalWidth() (int, error) {
	w := new(window)
	res, _, err := syscall.Syscall(sysIoctl,
		tty.Fd(),
		uintptr(syscall.TIOCGWINSZ),
		uintptr(unsafe.Pointer(w)),
	)
	if int(res) == -1 {
		return 0, err
	}
	return int(w.Col), nil
}

var oldState syscall.Termios

func lockEcho() (err error) {
	fd := tty.Fd()
	if _, _, e := syscall.Syscall6(sysIoctl, fd, ioctlReadTermios, uintptr(unsafe.Pointer(&oldState)), 0, 0, 0); e != 0 {
		err = fmt.Errorf("Can't get terminal settings: %v", e)
		return
	}

	newState := oldState
	newState.Lflag &^= syscall.ECHO
	newState.Lflag |= syscall.ICANON | syscall.ISIG
	newState.Iflag |= syscall.ICRNL
	if _, _, e := syscall.Syscall6(sysIoctl, fd, ioctlWriteTermios, uintptr(unsafe.Pointer(&newState)), 0, 0, 0); e != 0 {
		err = fmt.Errorf("Can't set terminal settings: %v", e)
		return
	}
	return
}

func unlockEcho() (err error) {
	fd := tty.Fd()
	if _, _, e := syscall.Syscall6(sysIoctl, fd, ioctlWriteTermios, uintptr(unsafe.Pointer(&oldState)), 0, 0, 0); e != 0 {
		err = fmt.Errorf("Can't set terminal settings")
	}
	return
}
