package main

import (
	"os"
	"time"

	helper "gitea.siteworxpro.com/Siteworxpro/aws-iam-anywhere-refresher/aws_signing_helper"
	"gitea.siteworxpro.com/Siteworxpro/aws-iam-anywhere-refresher/cmd"
	appConfig "gitea.siteworxpro.com/Siteworxpro/aws-iam-anywhere-refresher/config"
	"gitea.siteworxpro.com/Siteworxpro/aws-iam-anywhere-refresher/kube_client"
	"github.com/charmbracelet/log"
)

func main() {

	l := log.NewWithOptions(os.Stderr, log.Options{
		Level:           log.DebugLevel,
		ReportTimestamp: true,
		TimeFormat:      time.RFC3339,
	})

	l.Info("Starting credentials refresh")

	c := appConfig.NewConfig()

	err := c.Valid()
	if err != nil {
		l.Error("Invalid configuration", "error", err)
		os.Exit(1)
	}

	credentials, err := cmd.Run(&helper.CredentialsOpts{
		PrivateKeyId:        c.PrivateKey(),
		CertificateId:       c.Certificate(),
		CertificateBundleId: c.BundleId(),
		RoleArn:             c.RoleArn(),
		ProfileArnStr:       c.ProfileArn(),
		TrustAnchorArnStr:   c.TrustedAnchor(),
		SessionDuration:     int(c.SessionDuration()),
	})

	if err != nil {
		l.Error("Failed to refresh credentials", "error", err)

		os.Exit(3)
	}

	l.Info("Credentials refreshed")

	if c.FetchOnly() {
		l.Info("Fetch only mode, skipping secret update")

		l.Info("AccessKeyId", "access-key-id", credentials.AccessKeyId)
		l.Info("SecretAccessKey", "secret-access-key", credentials.SecretAccessKey)
		l.Info("SessionToken", "session-token", credentials.SessionToken)
		os.Exit(0)
	}

	client, err := kube_client.NewKubeClient()
	if err != nil {
		l.Error("Failed to create kubernetes client", "error", err)

		os.Exit(1)
	}

	_, err = client.GetSecret(c.Namespace(), c.Secret())
	if err != nil {
		l.Error("Failed to get secret", "error", err)
		l.Info("secret doesn't exist, trying to create")
		create, err := client.CreateSecret(c.Namespace(), credentials.ToSecret(c.Secret()))
		if err != nil {
			l.Error("Failed to create secret", "error", err)

			os.Exit(1)
		}
		l.Info("Created secret", "created-time-stamp", create.CreationTimestamp.String())
	} else {
		update, err := client.UpdateSecret(c.Namespace(), credentials.ToSecret(c.Secret()))
		if err != nil {
			l.Error("Failed to update secret", "error", err)
			os.Exit(1)
		}
		l.Info("Updated secret", "updated-time-stamp", update.CreationTimestamp.String())
	}

	if c.RestartDeployments() {
		l.Info("Restarting deployments")
		deployments, err := client.ListDeployments(c.Namespace())
		if err != nil {
			l.Error("Failed to list deployments", "error", err)
			os.Exit(1)
		}

		err = client.RestartDeployments(c.Namespace(), deployments)
		if err != nil {
			l.Error("Failed to restart deployments", "error", err)
			os.Exit(1)
		}
	}

	l.Info("Done!")

	os.Exit(0)
}
