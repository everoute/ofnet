module github.com/contiv/ofnet

go 1.15

require (
	github.com/Sirupsen/logrus v0.8.8-0.20160119000032-f7f79f729e0f
	github.com/cenkalti/hub v1.0.1 // indirect
	github.com/cenkalti/rpc2 v0.0.0-20210604223624-c1acbc6ec984 // indirect
	github.com/contiv/libOpenflow v0.0.0-20200107061746-e3817550c83b
	github.com/contiv/libovsdb v0.0.0-20160406174930-bbc744d8ddc8
	github.com/kr/pretty v0.1.0 // indirect
	github.com/orcaman/concurrent-map v1.0.0
	github.com/stretchr/testify v1.8.2
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
)

replace (
	github.com/contiv/libOpenflow => github.com/echkenluo/libOpenflow v0.0.0-20230302095138-348e687604e6
	github.com/contiv/libovsdb => github.com/everoute/libovsdb v0.0.0-20230109020235-5be40f26b455
	github.com/osrg/gobgp => github.com/zwtop/gobgp v0.0.0-20210127101833-12edfc1f4514
)
