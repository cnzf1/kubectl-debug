module github.com/cnzf1/kubectl-debug

go 1.12

require (
	cloud.google.com/go v0.38.0
	contrib.go.opencensus.io/exporter/ocagent v0.6.0
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78
	github.com/Azure/go-autorest v11.2.8+incompatible
	github.com/MakeNowJust/heredoc v0.0.0-20171113091838-e9091a26100e
	github.com/Microsoft/go-winio v0.4.11
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5
	github.com/PuerkitoBio/purell v1.1.1
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578
	github.com/beorn7/perks v0.0.0-20180321164747-3a771d992973
	github.com/census-instrumentation/opencensus-proto v0.2.1
	github.com/cnzf1/gocore v1.1.4
	github.com/containerd/cgroups v0.0.0-20200407151229-7fc7a507c04c // indirect
	github.com/containerd/console v1.0.0 // indirect
	github.com/containerd/containerd v1.3.3
	github.com/containerd/continuity v0.0.0-20200413184840-d3ef23f19fbb // indirect
	github.com/containerd/fifo v0.0.0-20200410184934-f15a3290365b // indirect
	github.com/containerd/ttrpc v1.0.0 // indirect
	github.com/containerd/typeurl v1.0.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/docker/distribution v2.7.1-0.20190205005809-0d3efadf0154+incompatible // 2020-04-15 d : https://github.com/containerd/containerd/issues/3031
	github.com/docker/docker v0.0.0-20171023200535-7848b8beb9d3
	github.com/docker/go-connections v0.4.0
	github.com/docker/go-events v0.0.0-20190806004212-e31b211e4f1c // indirect
	github.com/docker/go-units v0.4.0
	github.com/docker/spdystream v0.0.0-20181023171402-6480d4af844c
	github.com/evanphx/json-patch v4.1.0+incompatible
	github.com/exponent-io/jsonpath v0.0.0-20151013193312-d6023ce2651d
	github.com/go-openapi/jsonpointer v0.19.0
	github.com/go-openapi/jsonreference v0.19.0
	github.com/go-openapi/spec v0.19.0
	github.com/go-openapi/swag v0.19.0
	github.com/gogo/googleapis v1.3.2 // indirect
	github.com/gogo/protobuf v1.3.1
	github.com/golang/protobuf v1.3.2
	github.com/google/btree v1.0.0
	github.com/google/gofuzz v0.0.0-20170612174753-24818f796faf
	github.com/google/uuid v1.1.1
	github.com/googleapis/gnostic v0.2.0
	github.com/gophercloud/gophercloud v0.0.0-20181221023737-94924357ebf6
	github.com/gregjones/httpcache v0.0.0-20181110185634-c63ab54fda8f
	github.com/imdario/mergo v0.3.6
	github.com/inconshreveable/mousetrap v1.0.0
	github.com/json-iterator/go v1.1.5
	github.com/konsorten/go-windows-terminal-sequences v1.0.2
	github.com/mailru/easyjson v0.0.0-20190312143242-1de009706dbe
	github.com/matttproud/golang_protobuf_extensions v1.0.1
	github.com/mitchellh/go-wordwrap v1.0.0
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd
	github.com/modern-go/reflect2 v0.0.0-20180701023420-4b7aa43c6742
	github.com/opencontainers/go-digest v1.0.0-rc1
	github.com/opencontainers/image-spec v1.0.1
	github.com/opencontainers/runc v0.1.1 // indirect
	github.com/opencontainers/runtime-spec v1.0.2
	github.com/pborman/uuid v0.0.0-20180906182336-adf5a7427709
	github.com/petar/GoLLRB v0.0.0-20130427215148-53be0d36a84c
	github.com/peterbourgon/diskv v2.0.1+incompatible
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v0.9.2
	github.com/prometheus/client_model v0.0.0-20180712105110-5c3871d89910
	github.com/prometheus/common v0.0.0-20181218105931-67670fe90761
	github.com/prometheus/procfs v0.0.0-20181204211112-1dc9a6cbc91a
	github.com/rs/xid v1.4.0
	github.com/russross/blackfriday v0.0.0-20151117072312-300106c228d5
	github.com/shurcooL/sanitized_anchor_name v1.0.0
	github.com/sirupsen/logrus v1.4.2
	github.com/spf13/cobra v0.0.3
	github.com/spf13/pflag v1.0.3
	github.com/syndtr/gocapability v0.0.0-20180916011248-d98352740cb2 // indirect
	github.com/urfave/cli v1.22.4 // indirect
	go.opencensus.io v0.22.0
	golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2
	golang.org/x/net v0.0.0-20190628185345-da137c7871d7
	golang.org/x/oauth2 v0.0.0-20190604053449-0f29369cfe45
	golang.org/x/sync v0.0.0-20190423024810-112230192c58
	golang.org/x/sys v0.0.0-20200120151820-655fe14d7479
	golang.org/x/text v0.3.2
	golang.org/x/time v0.0.0-20181108054448-85acf8d2951c
	google.golang.org/api v0.7.0
	google.golang.org/appengine v1.5.0
	google.golang.org/genproto v0.0.0-20190716160619-c506a9f90610
	google.golang.org/grpc v1.22.0
	gopkg.in/inf.v0 v0.9.1
	gopkg.in/yaml.v2 v2.4.0
	k8s.io/api v0.0.0-20181130031204-d04500c8c3dd
	k8s.io/apimachinery v0.0.0-20190221213512-86fb29eff628
	k8s.io/apiserver v0.0.0-20181220070914-ce7b605bead3
	k8s.io/cli-runtime v0.0.0-20190228180923-a9e421a79326
	k8s.io/client-go v0.0.0-20190228174230-b40b2a5939e4
	k8s.io/klog v0.1.0
	k8s.io/kube-openapi v0.0.0-20190320154901-5e45bb682580
	k8s.io/kubernetes v1.13.1
	k8s.io/utils v0.0.0-20181115163542-0d26856f57b3
	sigs.k8s.io/yaml v1.1.0
)
