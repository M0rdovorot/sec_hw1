FROM golang:alpine as build

ENV CGO_ENABLED=1

COPY . /project

WORKDIR /project

RUN apk add make git gcc musl-dev bash && go build -o ./bin/proxy cmd/proxy/main.go

#================================

FROM alpine:latest

WORKDIR /

COPY --from=build /project/bin/ /bin/

RUN apk add bash

CMD ["proxy"]