module github.com/cilium/tetragon/contrib/to_oscf

go 1.25.0

require (
	github.com/cilium/tetragon/api v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.77.0
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/cilium/tetragon/api => ../../api

require (
	github.com/kr/pretty v0.3.1 // indirect
	golang.org/x/net v0.46.1-0.20251013234738-63d1a5100f82 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/text v0.30.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251022142026-3a174f9686a8 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)
