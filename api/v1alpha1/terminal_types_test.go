/*
SPDX-FileCopyrightText: 2021 SAP SE or an SAP affiliate company and Gardener contributors

SPDX-License-Identifier: Apache-2.0
*/

package v1alpha1

import (
	. "github.com/onsi/ginkgo"
)

// These tests are written in BDD-style using Ginkgo framework. Refer to
// http://onsi.github.io/ginkgo to learn more.

var _ = Describe("Terminal", func() {
	var (
	//key              types.NamespacedName
	//created, fetched *Terminal
	)

	BeforeEach(func() {
		// Add any setup steps that needs to be executed before each test
	})

	AfterEach(func() {
		// Add any teardown steps that needs to be executed after each test
	})

	// Add Tests for OpenAPI validation (or additional CRD features) specified in
	// your API definition.
	// Avoid adding tests for vanilla CRUD operations because they would
	// test Kubernetes API server, which isn't the goal here.
	Context("Create API", func() {

		//It("should create an object successfully", func() {
		//
		//	key = types.NamespacedName{
		//		Name:      "foo",
		//		Namespace: "default",
		//	}
		//	created = &Terminal{
		//		ObjectMeta: metav1.ObjectMeta{
		//			Name:      "foo",
		//			Namespace: "default",
		//		}}
		//
		//	By("creating an API obj")
		//	Expect(k8sClient.Create(context.TODO(), created)).To(Succeed())
		//
		//	fetched = &Terminal{}
		//	Expect(k8sClient.Get(context.TODO(), key, fetched)).To(Succeed())
		//	Expect(fetched).To(Equal(created))
		//
		//	By("deleting the created object")
		//	Expect(k8sClient.Delete(context.TODO(), created)).To(Succeed())
		//	Expect(k8sClient.Get(context.TODO(), key, created)).ToNot(Succeed())
		//})

	})

})
