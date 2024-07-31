package main

import (
	"context"
	"encoding/base64"
	helper "git.s.int/rrise/aws-iam-anywhere-refresher/aws_signing_helper"
	"git.s.int/rrise/aws-iam-anywhere-refresher/cmd"
	appConfig "git.s.int/rrise/aws-iam-anywhere-refresher/config"
	v1k "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"log"
	"os"
	"time"
)

func main() {
	println("Starting credentials refresh")

	config, err := rest.InClusterConfig()
	if err != nil {
		println("Are you running in a cluster?")
		panic(err)
	}

	client, err := kubernetes.NewForConfig(config)

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

	secret := &v1k.Secret{
		ObjectMeta: v1.ObjectMeta{
			Name: c.Secret(),
			Labels: map[string]string{
				"managed-by": "aws-iam-anywhere-refresher",
			},
		},
		StringData: map[string]string{
			"AWS_ACCESS_KEY_ID":     credentials.AccessKeyId,
			"AWS_SECRET_ACCESS_KEY": credentials.SecretAccessKey,
			"AWS_SESSION_TOKEN":     credentials.SessionToken,
		},
	}

	_, err = client.CoreV1().Secrets(c.Namespace()).Get(context.TODO(), c.Secret(), v1.GetOptions{})
	if err != nil {
		println(err.Error())
		println("secret doesn't exist, trying to create")

		create, err := client.CoreV1().Secrets(c.Namespace()).Create(context.Background(), secret, v1.CreateOptions{})
		if err != nil {
			panic(err)
		}

		println("secret created")
		println(create.CreationTimestamp.String())

	} else {
		update, err := client.CoreV1().Secrets(c.Namespace()).Update(context.TODO(), secret, v1.UpdateOptions{})
		if err != nil {
			panic(err)
		}

		println("secret updated")
		println(update.CreationTimestamp.String())
	}

	if c.RestartDeployments() {
		println("Restarting deployments...")

		deployments, err := client.AppsV1().Deployments(c.Namespace()).List(context.TODO(), v1.ListOptions{
			LabelSelector: "iam-role-type=aws-iam-anywhere",
		})

		if err != nil {
			panic(err)
		}

		for _, deployment := range deployments.Items {
			println("Restarting deployment", deployment.Name)

			if deployment.Spec.Template.ObjectMeta.Annotations == nil {
				deployment.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
			}
			deployment.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
			_, err = client.AppsV1().Deployments(c.Namespace()).Update(context.TODO(), &deployment, v1.UpdateOptions{})
			if err != nil {
				println(err.Error())
			}
		}
	}

	println("Done!")

	os.Exit(0)
}
