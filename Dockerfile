FROM siteworxpro/golang:1.22.5 AS build

ENV GOPRIVATE=git.s.int
ENV GOPROXY=direct

WORKDIR /app

ADD . .

RUN go mod tidy && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on GOOS=linux go build -o /app/aws-iam-anywhere-refresher

FROM ubuntu AS runtime

WORKDIR /app

COPY --from=build /app/aws-iam-anywhere-refresher aws-iam-anywhere-refresher

RUN apt update && apt install -yqq ca-certificates

ENTRYPOINT ["/app/aws-iam-anywhere-refresher"]
