package config

import "git.s.int/packages/go/utilities/Env"

const (
	namespace          Env.EnvironmentVariable = "NAMESPACE"
	secretName         Env.EnvironmentVariable = "SECRET"
	roleArn            Env.EnvironmentVariable = "ROLE_ARN"
	profileArn         Env.EnvironmentVariable = "PROFILE_ARN"
	trustedAnchorArn   Env.EnvironmentVariable = "TRUSTED_ANCHOR_ARN"
	privateKey         Env.EnvironmentVariable = "PRIVATE_KEY"
	certificate        Env.EnvironmentVariable = "CERTIFICATE"
	sessionDuration    Env.EnvironmentVariable = "SESSION_DURATION"
	restartDeployments Env.EnvironmentVariable = "RESTART_DEPLOYMENTS"
)

type Config struct{}

func NewConfig() *Config {
	return &Config{}
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
	return privateKey.GetEnvString("")
}

func (Config) Certificate() string {
	return certificate.GetEnvString("")
}

func (Config) SessionDuration() int64 {
	return sessionDuration.GetEnvInt("SESSION_DURATION", 900)
}

func (Config) RestartDeployments() bool {
	return restartDeployments.GetEnvBool(false)
}
