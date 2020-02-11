package accessor_test

import (
	"code.cloudfoundry.org/lager"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/concourse/concourse/atc"
	"github.com/concourse/concourse/atc/api/accessor"
)

var _ = Describe("AccessorFactory", func() {
	var accessorFactory accessor.AccessFactory
	var access accessor.Access
	var key *rsa.PrivateKey
	var req *http.Request

	Describe("Create", func() {
		BeforeEach(func() {
			reader := rand.Reader
			bitSize := 2048
			var err error
			key, err = rsa.GenerateKey(reader, bitSize)
			Expect(err).NotTo(HaveOccurred())

			publicKey := &key.PublicKey
			//publicKey = rsa.GenerateKey(random, bits)
			accessorFactory = accessor.NewAccessFactory(publicKey)

			req, err = http.NewRequest("GET", "localhost:8080", nil)
			Expect(err).NotTo(HaveOccurred())
		})
		JustBeforeEach(func() {
			access = accessorFactory.Create(req, "some-action")
		})

		Context("when request has jwt token set", func() {
			BeforeEach(func() {
				token := jwt.New(jwt.SigningMethodRS256)
				tokenString, err := token.SignedString(key)
				Expect(err).NotTo(HaveOccurred())
				req.Header.Add("Authorization", fmt.Sprintf("BEARER %s", tokenString))
			})

			It("creates valid access object", func() {
				Expect(access).ToNot(BeNil())
			})
		})

		Context("when request has jwt token with invalid signing key", func() {
			BeforeEach(func() {
				mySigningKey := []byte("AllYourBase")

				token := jwt.New(jwt.SigningMethodHS256)
				tokenString, err := token.SignedString(mySigningKey)

				Expect(err).NotTo(HaveOccurred())
				req.Header.Add("Authorization", fmt.Sprintf("BEARER %s", tokenString))
			})

			It("creates valid access object", func() {
				Expect(access).ToNot(BeNil())
			})

		})
		Context("when request does not have jwt token set", func() {
			BeforeEach(func() {
				req.Header.Add("Authorization", "")
			})
			It("creates valid access object", func() {
				Expect(access).ToNot(BeNil())
			})
		})

		Context("when request does not have valid jwt token set", func() {
			BeforeEach(func() {
				req.Header.Add("Authorization", "blah-token")
			})
			It("creates valid access object", func() {
				Expect(access).ToNot(BeNil())
			})
		})
	})

	Describe("CustomizeRolesMapping", func() {
		var (
			accessorFactory accessor.AccessFactory
		)

		BeforeEach(func() {
			accessorFactory = accessor.NewAccessFactory(&rsa.PublicKey{})
		})

		JustBeforeEach(func() {
			customData := accessor.CustomActionRoleMap{
				"pipeline-operator": []string{atc.HijackContainer, atc.CreatePipelineBuild},
				"viewer":            []string{atc.GetPipeline},
			}

			logger := lager.NewLogger("test")
			err := accessorFactory.CustomizeActionRoleMap(logger, customData)
			Expect(err).NotTo(HaveOccurred())
		})

		It("should correctly customized", func() {
			found, roleOfAction := accessorFactory.RoleOfAction(atc.HijackContainer)
			Expect(found).To(BeTrue())
			Expect(roleOfAction).To(Equal("pipeline-operator"))

			found, roleOfAction = accessorFactory.RoleOfAction(atc.CreatePipelineBuild)
			Expect(found).To(BeTrue())
			Expect(roleOfAction).To(Equal("pipeline-operator"))

			found, roleOfAction = accessorFactory.RoleOfAction(atc.GetPipeline)
			Expect(found).To(BeTrue())
			Expect(roleOfAction).To(Equal("viewer"))
		})

		It("should keep un-customized actions", func() {
			found, roleOfAction := accessorFactory.RoleOfAction(atc.SaveConfig)
			Expect(found).To(BeTrue())
			Expect(roleOfAction).To(Equal("member"))

			found, roleOfAction = accessorFactory.RoleOfAction(atc.GetConfig)
			Expect(found).To(BeTrue())
			Expect(roleOfAction).To(Equal("viewer"))

			found, roleOfAction = accessorFactory.RoleOfAction(atc.GetCC)
			Expect(found).To(BeTrue())
			Expect(roleOfAction).To(Equal("viewer"))
		})
	})

	Describe("Roles action map", func() {
		var (
			accessorFactory accessor.AccessFactory
		)

		BeforeEach(func() {
			accessorFactory = accessor.NewAccessFactory(&rsa.PublicKey{})
		})

		It("contains a role for every api endpoint", func() {
			for _, route := range atc.Routes {
				found, _ := accessorFactory.RoleOfAction(route.Name)
				Expect(found).To(BeTrue(), fmt.Sprintf("endpoint %s has no role", route.Name))
			}
		})
	})
})
