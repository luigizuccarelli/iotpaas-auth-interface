package connectors

import (
	"fmt"

	"github.com/microlib/simple"
)

// Connections struct - all backend connections in a common object
type Connectors struct {
	Logger *simple.Logger
}

// NewclientConnections - used for "real" connections
func NewClientConnections(logger *simple.Logger) Clients {
	return &Connectors{Logger: logger}
}

func (c *Connectors) Error(msg string, val ...interface{}) {
	c.Logger.Error(fmt.Sprintf(msg, val...))
}

func (c *Connectors) Info(msg string, val ...interface{}) {
	c.Logger.Info(fmt.Sprintf(msg, val...))
}

func (c *Connectors) Debug(msg string, val ...interface{}) {
	c.Logger.Debug(fmt.Sprintf(msg, val...))
}

func (c *Connectors) Trace(msg string, val ...interface{}) {
	c.Logger.Trace(fmt.Sprintf(msg, val...))
}
