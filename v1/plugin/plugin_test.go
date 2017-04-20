// +build small medium

/*
http://www.apache.org/licenses/LICENSE-2.0.txt


Copyright 2016 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package plugin

import (
	"crypto/tls"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"os"

	log "github.com/Sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
)

func init() {
	// Filter out go test flags
	getOSArgs = func() []string {
		args := []string{}
		for _, v := range os.Args {
			if !strings.HasPrefix(v, "-test") {
				args = append(args, v)
			}
		}
		return args
	}
}

func TestPlugin(t *testing.T) {
	Convey("Basing on plugin lib routines", t, func() {
		var mockInputOutput = newMockInputOutput(libInputOutput)
		libInputOutput = mockInputOutput
		Convey("collector plugin should start successfully", func() {
			i := StartCollector(newMockCollector(), "collector", 0, Exclusive(true), RoutingStrategy(1))
			So(i, ShouldEqual, 0)
		})
		Convey("processor plugin should start successfully", func() {
			j := StartProcessor(newMockProcessor(), "processor", 1, Exclusive(false))
			So(j, ShouldEqual, 0)
		})
		Convey("publisher plugin should start successfully", func() {
			k := StartPublisher(newMockPublisher(), "publisher", 2, Exclusive(false))
			So(k, ShouldEqual, 0)
		})
		Reset(func() {
			libInputOutput = mockInputOutput.prevInputOutput
		})
	})

}

func TestParsingArgs(t *testing.T) {
	Convey("With plugin lib parsing command line arguments", t, func() {
		mockInputOutput := newMockInputOutput(libInputOutput)
		libInputOutput = mockInputOutput
		Convey("ListenPort should be properly parsed", func() {
			mockInputOutput.mockArg = `{"ListenPort":"4414"}`
			args, err := getArgs()
			So(err, ShouldBeNil)
			So(args.ListenPort, ShouldEqual, "4414")
		})
		Convey("PingTimeoutDuration should be properly parsed", func() {
			mockInputOutput.mockArg = `{"PingTimeoutDuration":3141}`
			args, err := getArgs()
			So(err, ShouldBeNil)
			So(args.PingTimeoutDuration, ShouldEqual, 3141)
		})
		Reset(func() {
			libInputOutput = mockInputOutput.prevInputOutput
		})
	})
}

func TestPassingPluginMeta(t *testing.T) {
	Convey("With plugin lib transferring plugin meta", t, func() {
		log.SetLevel(log.DebugLevel)
		mockInputOutput := newMockInputOutput(libInputOutput)
		libInputOutput = mockInputOutput
		Convey("all meta arguments should be present in plugin response", func() {
			i := StartPublisher(newMockPublisher(), "mock-publisher-for-meta", 9, Exclusive(true), ConcurrencyCount(11), RoutingStrategy(StickyRouter), CacheTTL(305*time.Millisecond), rpcType(gRPC))
			So(i, ShouldEqual, 0)
			var response preamble
			err := json.Unmarshal([]byte(mockInputOutput.output[0]), &response)
			if err != nil {
				panic(err)
			}
			var actMeta = response.Meta
			So(actMeta.CacheTTL, ShouldEqual, 305*time.Millisecond)
			So(actMeta.RoutingStrategy, ShouldEqual, StickyRouter)
			So(actMeta.RPCType, ShouldEqual, gRPC)
			So(actMeta.ConcurrencyCount, ShouldEqual, 11)
			So(actMeta.Exclusive, ShouldEqual, true)
			So(actMeta.Version, ShouldEqual, 9)
			So(actMeta.Name, ShouldEqual, "mock-publisher-for-meta")
			So(actMeta.Type, ShouldEqual, publisherType)
		})
		Reset(func() {
			libInputOutput = mockInputOutput.prevInputOutput
		})
	})
}

func TestApplySecurityArgsToMeta(t *testing.T) {
	Convey("With plugin lib accepting security args", t, func() {
		m := newMeta(processorType, "test-processor", 3)
		args := &Arg{}
		Convey("paths to certificate and key files should be properly passed to plugin meta", func() {
			args.CertPath = "some-cert-path"
			args.KeyPath = "some-key-path"
			args.TLSEnabled = true
			err := applySecurityArgsToMeta(m, args)
			So(err, ShouldBeNil)
			So(m.CertPath, ShouldEqual, "some-cert-path")
			So(m.KeyPath, ShouldEqual, "some-key-path")
			So(m.TLSEnabled, ShouldEqual, true)
		})
		Convey("paths to certificate and key files must not be set if TLS is not enabled", func() {
			args.TLSEnabled = false
			err := applySecurityArgsToMeta(m, args)
			So(err, ShouldBeNil)
			So(m.CertPath, ShouldEqual, "")
			So(m.KeyPath, ShouldEqual, "")
			So(m.TLSEnabled, ShouldEqual, false)
		})
		Convey("paths to certificate file should be allowed only when TLS is enabled with a flag", func() {
			args.CertPath = "some-cert-path"
			err := applySecurityArgsToMeta(m, args)
			So(err, ShouldNotBeNil)
		})
		Convey("paths to key file should be allowed only when TLS is enabled with a flag", func() {
			args.KeyPath = "some-key-path"
			err := applySecurityArgsToMeta(m, args)
			So(err, ShouldNotBeNil)
		})
		Convey("enabling TLS with a flag without certificate path is an error", func() {
			args.KeyPath = "some-key-path"
			args.TLSEnabled = true
			err := applySecurityArgsToMeta(m, args)
			So(err, ShouldNotBeNil)
		})
		Convey("enabling TLS with a flag without key path is an error", func() {
			args.CertPath = "some-cert-path"
			args.TLSEnabled = true
			err := applySecurityArgsToMeta(m, args)
			So(err, ShouldNotBeNil)
		})
	})
}

func TestMakeTLSConfig(t *testing.T) {
	Convey("Being security-aware", t, func() {
		tlsSetupInstance := &tlsServerDefaultSetup{}
		Convey("plugin lib should use TLS config requiring verified clients and specific cipher suites", func() {
			config := tlsSetupInstance.makeTLSConfig()
			So(config.ClientAuth, ShouldEqual, tls.RequireAndVerifyClientCert)
			So(config.PreferServerCipherSuites, ShouldEqual, true)
			So(config.CipherSuites, ShouldNotBeEmpty)
		})
	})
}
