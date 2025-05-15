FROM siteworxpro/golang:1.24.3 AS build

WORKDIR /app

ADD . .

ENV GOPRIVATE=git.siteworxpro.com

RUN go mod download && go build -o aws-iam-anywhere-refresher .

FROM ubuntu:latest AS runtime

RUN apt update && apt install -yq ca-certificates curl
RUN curl -Ls https://siteworxpro.com/hosted/Siteworx+Root+CA.pem -o /usr/local/share/ca-certificates/sw.crt \
    && update-ca-certificates

WORKDIR /app

COPY --from=build /app/aws-iam-anywhere-refresher /app/aws-iam-anywhere-refresher

RUN useradd -b /app iam && \
    chown iam:iam /app/aws-iam-anywhere-refresher
USER iam

ENTRYPOINT ["/app/aws-iam-anywhere-refresher"]
