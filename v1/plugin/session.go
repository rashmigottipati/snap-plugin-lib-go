package plugin

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"net/http/pprof"

	log "github.com/Sirupsen/logrus"
	"github.com/julienschmidt/httprouter"
)

// Arg represents arguments passed to startup of Plugin
type Arg struct {
	// Plugin log level, see logrus.Loglevel
	LogLevel int
	// Ping timeout duration
	PingTimeoutDuration time.Duration

	// The listen port
	ListenPort string

	// enable pprof
	Pprof bool

	// Path to TLS certificate file for a TLS server
	CertPath string

	// Path to TLS private key file for a TLS server
	KeyPath string

	// Flag requesting server to establish TLS channel
	TLSEnabled bool
}

// getArgs returns plugin args or default ones
func getArgs() (*Arg, error) {
	osArgs := libInputOutput.readOSArgs()
	// default parameters - can be parsed as JSON
	paramStr := "{}"
	if len(osArgs) > 1 && osArgs[1] != "" {
		paramStr = osArgs[1]
	}
	arg := &Arg{}
	err := json.Unmarshal([]byte(paramStr), arg)
	if err != nil {
		return nil, err
	}

	return arg, nil
}

func startPprof() (string, error) {
	router := httprouter.New()
	router.GET("/debug/pprof/", index)
	router.GET("/debug/pprof/block", index)
	router.GET("/debug/pprof/goroutine", index)
	router.GET("/debug/pprof/heap", index)
	router.GET("/debug/pprof/threadcreate", index)
	router.GET("/debug/pprof/cmdline", cmdline)
	router.GET("/debug/pprof/profile", profile)
	router.GET("/debug/pprof/symbol", symbol)
	router.GET("/debug/pprof/trace", trace)
	addr, err := net.ResolveTCPAddr("tcp", ":0")
	if err != nil {
		return "", err
	}

	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return "", err
	}

	go func() {
		log.Fatal(http.Serve(l, router))
	}()

	return fmt.Sprintf("%d", l.Addr().(*net.TCPAddr).Port), nil
}

func index(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	pprof.Index(w, r)
}

func cmdline(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	pprof.Cmdline(w, r)
}

func profile(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	pprof.Profile(w, r)
}

func symbol(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	pprof.Symbol(w, r)
}

func trace(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	pprof.Trace(w, r)
}
