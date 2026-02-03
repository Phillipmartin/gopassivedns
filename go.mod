module github.com/Phillipmartin/gopassivedns

go 1.24.7

replace github.com/Sirupsen/logrus => github.com/sirupsen/logrus v1.9.3

require (
	github.com/Sirupsen/logrus v0.0.0-00010101000000-000000000000
	github.com/google/gopacket v1.1.19
	github.com/pquerna/ffjson v0.0.0-20190930134022-aa0246cd15f7
	github.com/quipo/statsd v0.0.0-20180118161217-3d6a5565f314
	github.com/vmihailenco/msgpack v4.0.4+incompatible
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
)

require (
	github.com/golang/protobuf v1.5.2 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/stretchr/testify v1.10.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/protobuf v1.26.0 // indirect
)
