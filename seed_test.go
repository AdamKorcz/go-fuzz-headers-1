package gofuzzheaders

import (
	"testing"
	corev1 "k8s.io/api/core/v1"
)

func TestGenerateSeed(t *testing.T) {
	pod := &corev1.Pod{}
	c := NewSeedGenerator()
	s := c.GenerateSeed(pod)
	f := NewConsumer(s)
	f.GenerateStruct(pod)
	//t.Log(err)
	t.Logf("%+v\n", pod.TypeMeta.Kind)
	t.Logf("%+v\n", pod.TypeMeta.APIVersion)
	t.Logf("%+v\n", pod.ObjectMeta.Name)
	t.Logf("%+v\n", pod.ObjectMeta.GenerateName)
	t.Logf("%+v\n", pod.ObjectMeta.Namespace)
	t.Logf("%+v\n", pod.ObjectMeta.SelfLink)
	t.Logf("%+v\n", pod.ObjectMeta.ResourceVersion)
	t.Logf("%+v\n", pod.ObjectMeta.Generation)
	t.Logf("%+v\n", *pod.ObjectMeta.DeletionGracePeriodSeconds)
	t.Logf("Labels: %+v\n", pod.ObjectMeta.Labels)
	t.Logf("%+v\n", pod.ObjectMeta.Annotations)
	t.Logf("%+v\n", pod.ObjectMeta.OwnerReferences)
	t.Logf("%+v\n", pod.ObjectMeta.Finalizers)
	//t.Logf("len(pod.Spec.Containers): %d", len(pod.Spec.Containers))
	t.Log(s[0:200])
	t.Fatal("Done")
}