package sarif

import "time"

// Invocation describes the runtime environment of the analysis tool run.
type Invocation struct {
	Account                            *string                  `json:"account,omitempty"`
	Arguments                          []string                 `json:"arguments,omitempty"`
	CommandLine                        *string                  `json:"commandLine,omitempty"`
	EndTimeUTC                         *time.Time               `json:"endTimeUtc,omitempty"`
	EnvironmentVariables               map[string]string        `json:"environmentVariables,omitempty"`
	ExecutableLocation                 *ArtifactLocation        `json:"executableLocation,omitempty"`
	ExecutionSuccessful                *bool                    `json:"executionSuccessful"`
	ExitCode                           *int                     `json:"exitCode,omitempty"`
	ExitCodeDescription                *string                  `json:"exitCodeDescription,omitempty"`
	ExitSignalName                     *string                  `json:"exitSignalName,omitempty"`
	ExitSignalNumber                   *int                     `json:"exitSignalNumber,omitempty"`
	Machine                            *string                  `json:"machine,omitempty"`
	NotificationConfigurationOverrides []*ConfigurationOverride `json:"notificationConfigurationOverrides,omitempty"`
	ProcessID                          *int                     `json:"processId,omitempty"`
	ProcessStartFailureMessage         *string                  `json:"processStartFailureMessage,omitempty"`
	ResponseFiles                      []*ArtifactLocation      `json:"responseFiles,omitempty"`
	RuleConfigurationOverrides         []*ConfigurationOverride `json:"ruleConfigurationOverrides,omitempty"`
	StartTimeUTC                       *time.Time               `json:"startTimeUtc,omitempty"`
	Stderr                             *ArtifactLocation        `json:"stderr,omitempty"`
	Stdin                              *ArtifactLocation        `json:"stdin,omitempty"`
	Stdout                             *ArtifactLocation        `json:"stdout,omitempty"`
	StdoutStderr                       *ArtifactLocation        `json:"stdoutStderr,omitempty"`
	ToolConfigurationNotifications     []*Notification          `json:"toolConfigurationNotifications,omitempty"`
	ToolExecutionNotifications         []*Notification          `json:"toolExecutionNotifications,omitempty"`
	WorkingDirectory                   *ArtifactLocation        `json:"workingDirectory,omitempty"`
	PropertyBag
}

// NewInvocation creates a new Invocation and returns a pointer to it
func NewInvocation() *Invocation {
	return &Invocation{}
}

// WithAccount sets the Account
func (invocation *Invocation) WithAccount(account string) *Invocation {
	invocation.Account = &account
	return invocation
}

// WithArguments sets the Arguments
func (invocation *Invocation) WithArguments(arguments []string) *Invocation {
	invocation.Arguments = arguments
	return invocation
}

// AddArgument ...
func (invocation *Invocation) AddArgument(argument string) {
	invocation.Arguments = append(invocation.Arguments, argument)
}

// WithCommanLine sets the CommanLine
func (invocation *Invocation) WithCommanLine(commandLine string) *Invocation {
	invocation.CommandLine = &commandLine
	return invocation
}

// WithEndTimeUTC sets the instant when the invocation ended and returns the same Invocation.
func (invocation *Invocation) WithEndTimeUTC(endTime time.Time) *Invocation {
	endTimeUTC := endTime.UTC()
	invocation.EndTimeUTC = &endTimeUTC
	return invocation
}

// WithEnvironmentVariables sets the EnvironmentVariables
func (invocation *Invocation) WithEnvironmentVariables(environmentVariables map[string]string) *Invocation {
	invocation.EnvironmentVariables = environmentVariables
	return invocation
}

// SetEnvironmentVariable ...
func (invocation *Invocation) SetEnvironmentVariable(name, value string) {
	invocation.EnvironmentVariables[name] = value
}

// WithExecutableLocation sets the ExecutableLocation
func (invocation *Invocation) WithExecutableLocation(executableLocation *ArtifactLocation) *Invocation {
	invocation.ExecutableLocation = executableLocation
	return invocation
}

// WithExecutionSuccess sets the ExecutionSuccess
func (invocation *Invocation) WithExecutionSuccess(executionSuccessful bool) *Invocation {
	invocation.ExecutionSuccessful = &executionSuccessful
	return invocation
}

// WithExitCode sets the ExitCode
func (invocation *Invocation) WithExitCode(exitCode int) *Invocation {
	invocation.ExitCode = &exitCode
	return invocation
}

// WithExitCodeDescription sets the ExitCodeDescription
func (invocation *Invocation) WithExitCodeDescription(exitCodeDescription string) *Invocation {
	invocation.ExitCodeDescription = &exitCodeDescription
	return invocation
}

// WithExitSignalNumber sets the ExitSignalNumber
func (invocation *Invocation) WithExitSignalNumber(exitSignalNumber int) *Invocation {
	invocation.ExitSignalNumber = &exitSignalNumber
	return invocation
}

// WithExitSignalName sets the ExitSignalName
func (invocation *Invocation) WithExitSignalName(exitSignalName string) *Invocation {
	invocation.ExitSignalName = &exitSignalName
	return invocation
}

// WithMachine sets the Machine
func (invocation *Invocation) WithMachine(machine string) *Invocation {
	invocation.Machine = &machine
	return invocation
}

// WithNotificationConfigurationOverrides sets the NotificationConfigurationOverrides
func (invocation *Invocation) WithNotificationConfigurationOverrides(overrides []*ConfigurationOverride) *Invocation {
	invocation.NotificationConfigurationOverrides = overrides
	return invocation
}

// AddNotificationConfigurationOverride ...
func (invocation *Invocation) AddNotificationConfigurationOverride(override *ConfigurationOverride) {
	invocation.NotificationConfigurationOverrides = append(invocation.NotificationConfigurationOverrides, override)
}

// WithProcessID sets the ProcessID
func (invocation *Invocation) WithProcessID(processID int) *Invocation {
	invocation.ProcessID = &processID

	return invocation
}

// WithProcessStartFailureMessage sets the ProcessStartFailureMessage
func (invocation *Invocation) WithProcessStartFailureMessage(failureMessage string) *Invocation {
	invocation.ProcessStartFailureMessage = &failureMessage
	return invocation
}

// WithResponseFiles sets the ResponseFiles
func (invocation *Invocation) WithResponseFiles(responseFiles []*ArtifactLocation) *Invocation {
	invocation.ResponseFiles = responseFiles
	return invocation
}

// AddResponseFile ...
func (invocation *Invocation) AddResponseFile(responseFile *ArtifactLocation) {
	invocation.ResponseFiles = append(invocation.ResponseFiles, responseFile)
}

// WithRuleConfigurationOverrides sets the RuleConfigurationOverrides
func (invocation *Invocation) WithRuleConfigurationOverrides(overrides []*ConfigurationOverride) *Invocation {
	invocation.RuleConfigurationOverrides = overrides
	return invocation
}

// AddRuleConfigurationOverride ...
func (invocation *Invocation) AddRuleConfigurationOverride(override *ConfigurationOverride) {
	invocation.RuleConfigurationOverrides = append(invocation.RuleConfigurationOverrides, override)
}

// WithStartTimeUTC sets the instant when the invocation started and returns the same Invocation.
func (invocation *Invocation) WithStartTimeUTC(startTime time.Time) *Invocation {
	startTimeUTC := startTime.UTC()
	invocation.StartTimeUTC = &startTimeUTC
	return invocation
}

// WithStdErr sets the StdErr
func (invocation *Invocation) WithStdErr(stdErr *ArtifactLocation) *Invocation {
	invocation.Stderr = stdErr
	return invocation
}

// WithStdIn sets the StdIn
func (invocation *Invocation) WithStdIn(stdIn *ArtifactLocation) *Invocation {
	invocation.Stdin = stdIn
	return invocation
}

// WithStdout sets the Stdout
func (invocation *Invocation) WithStdout(stdOut *ArtifactLocation) *Invocation {
	invocation.Stdout = stdOut
	return invocation
}

// WithStdoutStderr sets the StdoutStderr
func (invocation *Invocation) WithStdoutStderr(stdoutStderr *ArtifactLocation) *Invocation {
	invocation.StdoutStderr = stdoutStderr
	return invocation
}

// WithToolConfigurationNotifications sets the ToolConfigurationNotifications
func (invocation *Invocation) WithToolConfigurationNotifications(toolConfigNotifications []*Notification) *Invocation {
	invocation.ToolConfigurationNotifications = toolConfigNotifications
	return invocation
}

// AddToolConfigurationNotification ...
func (invocation *Invocation) AddToolConfigurationNotification(toolConfigNotification *Notification) {
	invocation.ToolConfigurationNotifications = append(invocation.ToolConfigurationNotifications, toolConfigNotification)
}

// WithToolExecutionNotifications sets the ToolExecutionNotifications
func (invocation *Invocation) WithToolExecutionNotifications(toolExecutionNotification []*Notification) *Invocation {
	invocation.ToolExecutionNotifications = toolExecutionNotification
	return invocation
}

// AddTToolExecutionNotification ...
func (invocation *Invocation) AddTToolExecutionNotification(toolExecutionNotification *Notification) {
	invocation.ToolExecutionNotifications = append(invocation.ToolExecutionNotifications, toolExecutionNotification)
}

// WithWorkingDirectory sets the current working directory of the invocation and returns the same Invocation.
func (invocation *Invocation) WithWorkingDirectory(workingDirectory *ArtifactLocation) *Invocation {
	invocation.WorkingDirectory = workingDirectory
	return invocation
}
