package plugin

import "github.com/urfave/cli"
import "time"

var (
	flConfig = cli.StringFlag{
		Name:  "config",
		Usage: "config file to use",
	}
	// If no port was provided we let the OS select a port for us.
	// This is safe as address is returned in the Response and keep
	// alive prevents unattended plugins.
	flPort = cli.StringFlag{
		Name:  "port",
		Usage: "port to listen on",
	}
	// If PingTimeoutDuration was provided we set it
	flLogLevel = cli.IntFlag{
		Name:  "log-level",
		Usage: "log level - 0:panic 1:fatal 2:error 3:warn 4:info 5:debug",
		Value: 2,
	}
	flPingTimeout = cli.DurationFlag{
		Name:  "timeout",
		Usage: "how much time must elapse before a lack of healthcheck results in a timeout",
		Value: time.Millisecond * 1500,
	}
	flPprof = cli.BoolFlag{
		Name:  "pprof",
		Usage: "set pprof",
	}
	flTLS = cli.BoolFlag{
		Name:  "tls",
		Usage: "enable TLS",
	}
	flCertPath = cli.StringFlag{
		Name:  "certPath",
		Usage: "necessary to provide when TLS enabled",
	}
	flKeyPath = cli.StringFlag{
		Name:  "keyPath",
		Usage: "necessary to provide when TLS enabled",
	}
	flStandAlone = cli.BoolFlag{
		Name:  "stand-alone",
		Usage: "enable stand alone plugin",
	}
	flHTTPPort = cli.IntFlag{
		Name:  "stand-alone-port",
		Usage: "specify http port when standAlone is set",
		Value: 8181,
	}
)
