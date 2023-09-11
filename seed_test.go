package gofuzzheaders

import (
	"testing"
	corev1 "k8s.io/api/core/v1"
)

func TestGenerateSeed(t *testing.T) {
	pod := &corev1.Pod{}
	c := NewSeedGenerator()
	c.GenerateStruct(pod)
}