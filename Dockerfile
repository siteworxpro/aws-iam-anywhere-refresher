FROM siteworxpro/golang:1.23.1 AS build

ENV GOPRIVATE=git.s.int
ENV GOPROXY=direct

WORKDIR /app

ADD . .

RUN go mod tidy && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on GOOS=linux go build -o /app/aws-iam-anywhere-refresher

FROM alpine:3 AS runtime

WORKDIR /app

COPY --from=build /app/aws-iam-anywhere-refresher aws-iam-anywhere-refresher

ENTRYPOINT ["/app/aws-iam-anywhere-refresher"]
