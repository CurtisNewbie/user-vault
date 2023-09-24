FROM golang:1.18-alpine as build
LABEL author="Yongjie Zhuang"
LABEL descrption="User-Vault, a simple user management service"

RUN apk --no-cache add tzdata
WORKDIR /go/src/build/

# for golang env
RUN go env -w GO111MODULE=on

# dependencies
COPY go.mod .
COPY go.sum .

RUN go mod download

# build executable
COPY . .
RUN go build -o main

FROM alpine:3.17
WORKDIR /usr/src/
COPY --from=build /go/src/build/main ./main
COPY --from=build /usr/share/zoneinfo /usr/share/zoneinfo

ENV TZ=Asia/Shanghai

CMD ["./main", "profile='prod'", "configFile=/usr/src/config/app-conf-prod.yml"]
