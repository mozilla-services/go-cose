
install:
	# dev requirements
	go get -u github.com/stretchr/testify/assert

	mkdir -p test
	cd test && git clone https://github.com/cose-wg/Examples.git cose-wg-examples || true
	cd test && git clone https://github.com/g-k/cose-rust.git || true
	cd test/cose-rust && git checkout test-verify-cli


install-go-fuzz:
	# dev requirement
	go get -u github.com/dvyukov/go-fuzz/...

# sample generated with:
# for file in $(find . -name *.json); do jq '.output.cbor' < $file | tr -d \" | base64 --decode > $(echo $file | sed s/..// | tr '/' '_').cose; done
fuzz: install-go-fuzz
	mkdir -p workdir/corpus
	cp samples/*.cose workdir/corpus
	go-fuzz-build go.mozilla.org/cose
	go-fuzz -bin=./cose-fuzz.zip -workdir=workdir

coverage:
	go test -v -cover -race -coverprofile=coverage.out && go tool cover -html=coverage.out

what-todo:
	rg -g '**/*.go' -i TODO

goveralls:
	go get -u github.com/mattn/goveralls

smoketest-examples:
	go run example/sign.go
	go run example/verify.go

ci: goveralls install coverage
	goveralls -coverprofile=coverage.out -service=circle-ci -repotoken=$(COVERALLS_TOKEN)
