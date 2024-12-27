FROM siteworxpro/golang:1.23.4 AS build

ENV GOPRIVATE=git.s.int
ENV GOPROXY=direct

WORKDIR /app

ADD . .

RUN go mod tidy && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -o /app/aws-iam-anywhere-refresher

FROM alpine:latest AS runtime

WORKDIR /app

COPY --from=build /app/aws-iam-anywhere-refresher aws-iam-anywhere-refresher

RUN adduser -D -H iam && \
    chown iam:iam /app/aws-iam-anywhere-refresher
USER iam

ENTRYPOINT ["/app/aws-iam-anywhere-refresher"]
