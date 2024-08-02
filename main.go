package main

import (
	"encoding/base64"
	helper "git.s.int/rrise/aws-iam-anywhere-refresher/aws_signing_helper"
	"git.s.int/rrise/aws-iam-anywhere-refresher/cmd"
	appConfig "git.s.int/rrise/aws-iam-anywhere-refresher/config"
	"git.s.int/rrise/aws-iam-anywhere-refresher/kube_client"
	"log"
	"os"
)

func main() {
	println("Starting credentials refresh")

	client, err := kube_client.NewKubeClient()
	if err != nil {
		panic(err)
	}

	c := appConfig.NewConfig()

	privateKey, err := base64.StdEncoding.DecodeString(c.PrivateKey())
	if err != nil {
		log.Fatal("error:", err)
	}

	certificate, err := base64.StdEncoding.DecodeString(c.Certificate())
	if err != nil {
		log.Fatal("error:", err)
	}

	credentials, err := cmd.Run(&helper.CredentialsOpts{
		PrivateKeyId:  string(privateKey),
		CertificateId: string(certificate),
		CertIdentifier: helper.CertIdentifier{
			SystemStoreName: "MY",
		},
		RoleArn:           c.RoleArn(),
		ProfileArnStr:     c.ProfileArn(),
		TrustAnchorArnStr: c.TrustedAnchor(),
		SessionDuration:   int(c.SessionDuration()),
	})

	if err != nil {
		panic(err)
	}

	println("Got new credentials")

	_, err = client.GetSecret(c.Namespace(), c.Secret())
	if err != nil {
		println(err.Error())
		println("secret doesn't exist, trying to create")
		create, err := client.CreateSecret(c.Namespace(), credentials.ToSecret(c.Secret()))
		if err != nil {
			panic(err)
		}
		println("secret created")
		println(create.CreationTimestamp.String())
	} else {
		update, err := client.UpdateSecret(c.Namespace(), credentials.ToSecret(c.Secret()))
		if err != nil {
			panic(err)
		}
		println("secret updated")
		println(update.CreationTimestamp.String())
	}

	if c.RestartDeployments() {
		println("Restarting deployments...")
		deployments, err := client.ListDeployments(c.Namespace())
		if err != nil {
			panic(err)
		}

		err = client.RestartDeployments(c.Namespace(), deployments)
		if err != nil {
			panic(err)
		}
	}

	println("Done!")

	os.Exit(0)
}
