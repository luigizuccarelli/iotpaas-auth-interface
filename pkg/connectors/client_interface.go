package connectors

// Client Interface - used as a receiver and can be overriden for testing
type Clients interface {
	Error(string, ...interface{})
	Info(string, ...interface{})
	Debug(string, ...interface{})
	Trace(string, ...interface{})
}
