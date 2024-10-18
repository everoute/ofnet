module github.com/contiv/ofnet

go 1.19

require (
	github.com/contiv/libOpenflow v0.0.0-20200107061746-e3817550c83b
	github.com/contiv/libovsdb v0.0.0-20160406174930-bbc744d8ddc8
	github.com/orcaman/concurrent-map/v2 v2.0.1
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.8.2
)

require (
	github.com/cenkalti/hub v1.0.1 // indirect
	github.com/cenkalti/rpc2 v0.0.0-20210604223624-c1acbc6ec984 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/pretty v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/exp v0.0.0-20240409090435-93d18d7e34b8 // indirect
	golang.org/x/sys v0.0.0-20220715151400-c0bba94af5f8 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/klog v1.0.0 // indirect
)

replace (
	github.com/contiv/libOpenflow => github.com/everoute/libOpenflow v1.0.1-0.20241017045702-95ea206b1740
	github.com/contiv/libovsdb => github.com/everoute/libovsdb v0.0.0-20230109020235-5be40f26b455
	github.com/osrg/gobgp => github.com/zwtop/gobgp v0.0.0-20210127101833-12edfc1f4514
)
