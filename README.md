# AWS IAM Roles Anywhere Refresher


## Setup
[AWS IAM Roles Anywhere](https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html)

If you are running workloads outside of AWS it's recommended that you only use short lived IAM credentials.
Because those credentials expire they need to be refreshed on a schedule.

This image runs in a kubernetes cronjob and will create and save new IAM credentials in a secret.

*This container is not designed to run outside of kubernetes!*

## Docker hub and repo

- [docker image](https://hub.docker.com/repository/docker/siteworxpro/aws-iam-anywhere/general)
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
              env:
                - name: NAMESPACE
                  value: default
                - name: SECRET
                  value: aws-credentials
                - name: ROLE_ARN
                  value: arn:aws:iam::12345:role/my-role
                - name: PROFILE_ARN
                  value: arn:aws:rolesanywhere:us-east-1:12345:profile/bdf23662-32fe-482f-98f4-f10ba6afacd8
                - name: TRUSTED_ANCHOR_ARN
                  value: arn:aws:rolesanywhere:us-east-1:3123451:trust-anchor/23692607-2a1e-468d-80d4-dc78ce9d9b1a
                - name: CERTIFICATE
                  value: LS0...S0K
                - name: PRIVATE_KEY
                  value: LS0t...S0K
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

