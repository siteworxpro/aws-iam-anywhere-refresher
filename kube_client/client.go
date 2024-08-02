package kube_client

import (
	"context"
	v1a "k8s.io/api/apps/v1"
	v1c "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"time"
)

type kubeClient interface {
	GetSecret(namespace string, secretName string) (*v1c.Secret, error)
	CreateSecret(namespace string, secret *v1c.Secret) (*v1c.Secret, error)
	UpdateSecret(namespace string, secret *v1c.Secret) (*v1c.Secret, error)
	ListDeployments(namespace string) (*v1a.DeploymentList, error)
	RestartDeployments(namespace string, deployments *v1a.DeploymentList) error
}

type KubeClientImpl struct {
	kubeClient
	clientSet *kubernetes.Clientset
}

func NewKubeClient() (*KubeClientImpl, error) {

	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	client, err := kubernetes.NewForConfig(config)

	if err != nil {
		return nil, err
	}

	return &KubeClientImpl{
		clientSet: client,
	}, nil
}

func (k KubeClientImpl) GetSecret(namespace string, secretName string) (*v1c.Secret, error) {
	secret, err := k.clientSet.CoreV1().Secrets(namespace).Get(context.TODO(), secretName, v1.GetOptions{})

	if err != nil {
		return nil, err
	}

	return secret, nil
}

func (k KubeClientImpl) CreateSecret(namespace string, secret *v1c.Secret) (*v1c.Secret, error) {
	return k.clientSet.CoreV1().Secrets(namespace).Create(context.TODO(), secret, v1.CreateOptions{})
}

func (k KubeClientImpl) UpdateSecret(namespace string, secret *v1c.Secret) (*v1c.Secret, error) {
	return k.clientSet.CoreV1().Secrets(namespace).Update(context.TODO(), secret, v1.UpdateOptions{})
}

func (k KubeClientImpl) ListDeployments(namespace string) (*v1a.DeploymentList, error) {
	return k.clientSet.AppsV1().Deployments(namespace).List(context.TODO(), v1.ListOptions{
		LabelSelector: "iam-role-type=aws-iam-anywhere",
	})
}

func (k KubeClientImpl) RestartDeployments(namespace string, deployments *v1a.DeploymentList) error {
	for _, deployment := range deployments.Items {
		if deployment.Spec.Template.ObjectMeta.Annotations == nil {
			deployment.Spec.Template.ObjectMeta.Annotations = make(map[string]string)
		}

		deployment.Spec.Template.ObjectMeta.Annotations["kubectl.kubernetes.io/restartedAt"] = time.Now().Format(time.RFC3339)
		_, err := k.clientSet.AppsV1().Deployments(namespace).Update(context.TODO(), &deployment, v1.UpdateOptions{})
		if err != nil {
			return err
		}
	}

	return nil
}
