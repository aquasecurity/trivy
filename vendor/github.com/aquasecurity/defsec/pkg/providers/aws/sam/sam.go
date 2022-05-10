package sam

type SAM struct {
	APIs          []API
	Applications  []Application
	Functions     []Function
	HttpAPIs      []HttpAPI
	SimpleTables  []SimpleTable
	StateMachines []StateMachine
}
