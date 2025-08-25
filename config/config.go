package config

import (
	"encoding/base64"
	"fmt"
	"gitea.siteworxpro.com/golang-packages/utilities/Env"
	"regexp"
)

const (
	namespace          Env.EnvironmentVariable = "NAMESPACE"
	secretName         Env.EnvironmentVariable = "SECRET"
	roleArn            Env.EnvironmentVariable = "ROLE_ARN"
	profileArn         Env.EnvironmentVariable = "PROFILE_ARN"
	trustedAnchorArn   Env.EnvironmentVariable = "TRUSTED_ANCHOR_ARN"
	privateKey         Env.EnvironmentVariable = "PRIVATE_KEY"
	certificate        Env.EnvironmentVariable = "CERTIFICATE"
	bundleId           Env.EnvironmentVariable = "CA_CHAIN"
	sessionDuration    Env.EnvironmentVariable = "SESSION_DURATION"
	restartDeployments Env.EnvironmentVariable = "RESTART_DEPLOYMENTS"
	fetchOnly          Env.EnvironmentVariable = "FETCH_ONLY"
)

type Config struct{}

func NewConfig() *Config {
	return &Config{}
}

func (c Config) Valid() error {
	// Certificate Required
	if c.Certificate() == "" {
		return fmt.Errorf("certificate is required")
	}

	// Private Key Required
	if c.PrivateKey() == "" {
		return fmt.Errorf("private Key is required")
	}

	// Role ARN Required
	if c.RoleArn() == "" {
		return fmt.Errorf("role ARN is required")
	}

	if !regexp.MustCompile(`^arn:aws:iam::[0-9]{10,13}:role/[\w\D]*$`).MatchString(c.RoleArn()) {
		return fmt.Errorf("role ARN %s is invalid", c.RoleArn())
	}

	if c.ProfileArn() == "" {
		return fmt.Errorf("profile ARN is required")
	}

	if !regexp.MustCompile(`^arn:aws:rolesanywhere:[\w-]*:\d{10,12}:profile/[\w\D]*$`).MatchString(c.ProfileArn()) {
		return fmt.Errorf("profile ARN %s is invalid", c.ProfileArn())
	}

	// Trusted Anchor ARN Required
	if c.TrustedAnchor() == "" {
		return fmt.Errorf("trusted anchor ARN is required")
	}

	if !regexp.MustCompile(`^arn:aws:rolesanywhere:[\w-]*:\d{10,12}:trust-anchor/[\w\D]*$`).MatchString(c.TrustedAnchor()) {
		return fmt.Errorf("trusted anchor %s ARN is invalid", c.TrustedAnchor())
	}

	return nil
}

func (Config) BundleId() string {
	v, err := base64.StdEncoding.DecodeString(bundleId.GetEnvString(""))
	if err != nil {
		return ""
	}

	return string(v)
}

func (Config) FetchOnly() bool {
	return fetchOnly.GetEnvBool(false)
}

func (Config) Namespace() string {
	return namespace.GetEnvString("")
}

func (Config) Secret() string {
	return secretName.GetEnvString("aws-credentials")
}

func (Config) RoleArn() string {
	return roleArn.GetEnvString("")
}

func (Config) ProfileArn() string {
	return profileArn.GetEnvString("")
}

func (Config) TrustedAnchor() string {
	return trustedAnchorArn.GetEnvString("")
}

func (Config) PrivateKey() string {
	v, err := base64.StdEncoding.DecodeString(privateKey.GetEnvString(""))
	if err != nil {
		return ""
	}

	return string(v)
}

func (Config) Certificate() string {
	v, err := base64.StdEncoding.DecodeString(certificate.GetEnvString(""))
	if err != nil {
		return ""
	}

	return string(v)
}

func (Config) SessionDuration() int64 {
	return sessionDuration.GetEnvInt("SESSION_DURATION", 900)
}

func (Config) RestartDeployments() bool {
	return restartDeployments.GetEnvBool(false)
}
