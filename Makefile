default: test

ci: get test

get:
	go get -t -v ./...

lint:
	go get -u github.com/golang/lint/golint
	golint

test:
	go test -check.vv -cover ./...
