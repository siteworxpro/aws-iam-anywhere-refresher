# AWS IAM Roles Anywhere Refresher


## Setup
[AWS IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html)

If you are running workloads outside of AWS it's recommended that you only use short lived IAM credentials.
Because those credentials expire they need to be refreshed on a schedule.

This image runs in a kubernetes cronjob and will create and save new IAM credentials in a secret.

*This container is not designed to run outside of kubernetes!*

## Docker hub and repo

- [container image](https://hub.docker.com/repository/docker/siteworxpro/aws-iam-anywhere/general)
- [github.com](https://github.com/siteworxpro/aws-iam-anywhere-refresher)


## Environment Variables

- `SECRET`: the name of the secret containing the aws credentials (default=aws-credentials)
- `RESTART_DEPLOYMENTS` : restart deployments on success (default=false)
- `SESSION_DURATION` : how long credentials requested will be valid (default=900)
- `NAMESPACE` ***required*** : the namespace your cron pod is in
- `ROLE_ARN` ***required*** : the role arn to assume
- `PROFILE_ARN` ***required*** : the aim anywhere profile arn
- `TRUSTED_ANCHOR_ARN` ***required*** : the trusted anchor arn
- `PRIVATE_KEY` ***required*** : iam private key base64 encoded
- `CERTIFICATE` ***required*** : iam certificate base64 encoded
- `CA_CHAIN` : the certificate chain bundle if needed

```yaml

apiVersion: batch/v1
kind: CronJob
metadata:
  name: aws-iam-anywhere
spec:
  concurrencyPolicy: Forbid
  failedJobsHistoryLimit: 1
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: aws-iam-anywhere-refresher
          restartPolicy: Never
          containers:
            - name: refresher
              image: siteworxpro/aws-iam-anywhere
              imagePullPolicy: Always
              envFrom:
                - configMapRef:
                    name: aws-iam-anywhere
                - secretRef:
                    name: aws-iam-anywhere
  schedule: 00 * * * *
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: aws-iam-anywhere-refresher
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: aws-iam-anywhere-role
  namespace: aws-iam-anywhere
rules:
  - verbs:
      - list
      - update
    resources:
      - deployments
    apiGroups:
      - apps
  - verbs:
      - create
      - update
      - get
    resources:
      - secrets
    apiGroups:
      -
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: aws-iam-anywhere
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: aws-iam-anywhere-role
subjects:
  - kind: ServiceAccount
    name: aws-iam-anywhere-refresher
    namespace: default
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: aws-iam-anywhere
data:
  NAMESPACE: "default"
  SECRET: "aws-credentials"
  ROLE_ARN: "arn:aws:iam::12345:role/my-role"
  PROFILE_ARN: "arn:aws:rolesanywhere:us-east-1:12345:profile/bdf23662-32fe-482f-98f4-f10ba6afacd8"
  TRUSTED_ANCHOR_ARN: "arn:aws:rolesanywhere:us-east-1:12345:trust-anchor/23692607-2a1e-468d-80d4-dc78ce9d9b1a"
  RESTART_DEPLOYMENTS: "1"
---
apiVersion: v1
kind: Secret
metadata:
  name: aws-iam-anywhere
stringData:
  CERTIFICATE: "LS0t...S0tCg=="
  PRIVATE_KEY: "LS0t...S0K"

```

resulting secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  labels:
    managed-by: aws-iam-anywhere-refresher
  name: aws-credentials
  namespace: default
data:
  AWS_ACCESS_KEY_ID: QVN....lE=
  AWS_SECRET_ACCESS_KEY: WT...Qw==
  AWS_SESSION_TOKEN: SVFv...VzPQ==
```

## Restarting Deployments

You can optionally restart your deployments if needed. Set the `RESTART_DEPLOYMENTS` environment variable to `true`. If this isn't needed you can exclude the permission in the role above and the variable.

The process will list all deployments with the label `iam-role-type=aws-iam-anywhere` and restart them.

Be sure, if needed to avoid downtime, to configure your deployments readiness probes.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: aws-iam-anywhere
  namespace: aws-iam-anywhere
  labels:
    iam-role-type: aws-iam-anywhere
```

