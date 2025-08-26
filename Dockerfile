FROM siteworxpro/golang:1.24.6 AS build

WORKDIR /app

ADD . .

ENV GOPRIVATE=git.siteworxpro.com

RUN go mod tidy && go build -o aws-iam-anywhere-refresher .

FROM siteworxpro/alpine:3.21.4 AS runtime

WORKDIR /app

COPY --from=build /app/aws-iam-anywhere-refresher /app/aws-iam-anywhere-refresher

RUN apk add --no-cache gcompat

RUN adduser -Dh /app iam && \
    chown iam:iam /app/aws-iam-anywhere-refresher
USER iam

ENTRYPOINT ["/app/aws-iam-anywhere-refresher"]
