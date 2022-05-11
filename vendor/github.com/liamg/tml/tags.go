package tml

var fgTags = map[string]string{
	"red":          "\x1b[31m",
	"green":        "\x1b[32m",
	"yellow":       "\x1b[33m",
	"blue":         "\x1b[34m",
	"magenta":      "\x1b[35m",
	"cyan":         "\x1b[36m",
	"lightgrey":    "\x1b[37m",
	"darkgrey":     "\x1b[90m",
	"black":        "\x1b[30m",
	"lightred":     "\x1b[91m",
	"lightgreen":   "\x1b[92m",
	"lightyellow":  "\x1b[93m",
	"lightblue":    "\x1b[94m",
	"lightmagenta": "\x1b[95m",
	"lightcyan":    "\x1b[96m",
	"white":        "\x1b[97m",
}

var bgTags = map[string]string{
	"bg-red":          "\x1b[41m",
	"bg-green":        "\x1b[42m",
	"bg-yellow":       "\x1b[43m",
	"bg-blue":         "\x1b[44m",
	"bg-magenta":      "\x1b[45m",
	"bg-cyan":         "\x1b[46m",
	"bg-lightgrey":    "\x1b[47m",
	"bg-darkgrey":     "\x1b[40m",
	"bg-black":        "\x1b[40m",
	"bg-lightred":     "\x1b[101m",
	"bg-lightgreen":   "\x1b[102m",
	"bg-lightyellow":  "\x1b[103m",
	"bg-lightblue":    "\x1b[104m",
	"bg-lightmagenta": "\x1b[105m",
	"bg-lightcyan":    "\x1b[106m",
	"bg-white":        "\x1b[107m",
}

var attrTags = map[string]uint8{
	"bold":      bold,
	"dim":       dim,
	"italic":    italic,
	"underline": underline,
	"blink":     blink,
	"reverse":   reverse,
	"hidden":    hidden,
}
