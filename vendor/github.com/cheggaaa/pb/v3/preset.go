package pb

var (
	// Full - preset with all default available elements
	// Example: 'Prefix 20/100 [-->______] 20% 1 p/s ETA 1m Suffix'
	Full ProgressBarTemplate = `{{string . "prefix"}}{{counters . }} {{bar . }} {{percent . }} {{speed . }} {{rtime . "ETA %s"}}{{string . "suffix"}}`

	// Default - preset like Full but without elapsed time
	// Example: 'Prefix 20/100 [-->______] 20% 1 p/s ETA 1m Suffix'
	Default ProgressBarTemplate = `{{string . "prefix"}}{{counters . }} {{bar . }} {{percent . }} {{speed . }}{{string . "suffix"}}`

	// Simple - preset without speed and any timers. Only counters, bar and percents
	// Example: 'Prefix 20/100 [-->______] 20% Suffix'
	Simple ProgressBarTemplate = `{{string . "prefix"}}{{counters . }} {{bar . }} {{percent . }}{{string . "suffix"}}`
)
