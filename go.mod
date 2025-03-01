module github.com/pomerium/pomerium

go 1.16

require (
	contrib.go.opencensus.io/exporter/jaeger v0.2.1
	contrib.go.opencensus.io/exporter/prometheus v0.3.0
	contrib.go.opencensus.io/exporter/zipkin v0.1.2
	github.com/DataDog/opencensus-go-exporter-datadog v0.0.0-20200406135749-5c268882acf0
	github.com/btcsuite/btcutil v1.0.2
	github.com/caddyserver/certmagic v0.14.1
	github.com/cenkalti/backoff/v4 v4.1.1
	github.com/cespare/xxhash/v2 v2.1.1
	github.com/client9/misspell v0.3.4
	github.com/coreos/go-oidc/v3 v3.0.0
	github.com/envoyproxy/go-control-plane v0.9.9-0.20210512163311-63b5d3c536b0
	github.com/envoyproxy/protoc-gen-validate v0.6.1
	github.com/fsnotify/fsnotify v1.4.9
	github.com/go-chi/chi v1.5.4
	github.com/go-jose/go-jose/v3 v3.0.0
	github.com/go-redis/redis/v8 v8.11.1
	github.com/golang/mock v1.6.0
	github.com/golang/protobuf v1.5.2
	github.com/golangci/golangci-lint v1.41.1
	github.com/google/btree v1.0.1
	github.com/google/go-cmp v0.5.6
	github.com/google/go-jsonnet v0.17.0
	github.com/google/uuid v1.3.0
	github.com/gorilla/handlers v1.5.1
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/websocket v1.4.2
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/golang-lru v0.5.4
	github.com/lithammer/shortuuid/v3 v3.0.7
	github.com/martinlindhe/base36 v1.1.0
	github.com/mitchellh/hashstructure/v2 v2.0.2
	github.com/mitchellh/mapstructure v1.4.1
	github.com/natefinch/atomic v0.0.0-20200526193002-18c0533a5b09
	github.com/onsi/gocleanup v0.0.0-20140331211545-c1a5478700b5
	github.com/open-policy-agent/opa v0.31.0
	github.com/openzipkin/zipkin-go v0.2.5
	github.com/ory/dockertest/v3 v3.7.0
	github.com/pomerium/csrf v1.7.0
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/common v0.30.0
	github.com/prometheus/procfs v0.7.1
	github.com/prometheus/statsd_exporter v0.21.0 // indirect
	github.com/rjeczalik/notify v0.9.3-0.20201210012515-e2a77dcc14cf
	github.com/rs/cors v1.8.0
	github.com/rs/zerolog v1.23.0
	github.com/scylladb/go-set v1.0.2
	github.com/shirou/gopsutil/v3 v3.21.7
	github.com/skratchdot/open-golang v0.0.0-20200116055534-eef842397966
	github.com/spf13/cobra v1.2.1
	github.com/spf13/viper v1.8.1
	github.com/stretchr/testify v1.7.0
	github.com/tniswong/go.rfcx v0.0.0-20181019234604-07783c52761f
	github.com/tomnomnom/linkheader v0.0.0-20180905144013-02ca5825eb80
	github.com/yuin/gopher-lua v0.0.0-20200816102855-ee81675732da
	go.opencensus.io v0.23.0
	go.uber.org/zap v1.18.1
	golang.org/x/crypto v0.0.0-20210513164829-c07d793c2f9a
	golang.org/x/net v0.0.0-20210525063256-abc453219eb5
	golang.org/x/oauth2 v0.0.0-20210628180205-a41e5a781914
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	google.golang.org/api v0.52.0
	google.golang.org/genproto v0.0.0-20210722135532-667f2b7c528f
	google.golang.org/grpc v1.39.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/auth0.v5 v5.19.2
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)
