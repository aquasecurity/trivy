package tml

import "sync"

var disableFormatting bool
var formattingLock sync.RWMutex

func DisableFormatting() {
	formattingLock.Lock()
	defer formattingLock.Unlock()
	disableFormatting = true
}

func EnableFormatting() {
	formattingLock.Lock()
	defer formattingLock.Unlock()
	disableFormatting = false
}
