package cmd

import helper "git.s.int/rrise/aws-iam-anywhere-refresher/aws_signing_helper"

func Run(opts *helper.CredentialsOpts) (*helper.CredentialProcessOutput, error) {
	signer, signingAlgorithm, err := helper.GetSigner(opts)
	if err != nil {
		return nil, err
	}
	defer signer.Close()
	credentialProcessOutput, err := helper.GenerateCredentials(opts, signer, signingAlgorithm)

	if err != nil {
		return nil, err
	}

	return &credentialProcessOutput, nil
}
