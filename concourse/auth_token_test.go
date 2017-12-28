package concourse_test

import (
	"net/http"

	"github.com/concourse/skymarshal/provider"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/ghttp"
)

var _ = Describe("ATC Handler Auth Token", func() {
	Describe("AuthToken", func() {
		var expectedAuthToken provider.AuthToken

		BeforeEach(func() {
			expectedURL := "/auth/basic/token"
			expectedRawQuery := "team_name=some-team"

			expectedAuthToken = provider.AuthToken{
				Type:  "Bearer",
				Value: "gobbeldigook",
			}

			atcServer.AppendHandlers(
				ghttp.CombineHandlers(
					ghttp.VerifyRequest("GET", expectedURL, expectedRawQuery),
					ghttp.RespondWithJSONEncoded(http.StatusOK, expectedAuthToken),
				),
			)
		})

		It("returns the user's auth token", func() {
			token, err := team.AuthToken()
			Expect(err).NotTo(HaveOccurred())
			Expect(token).To(Equal(expectedAuthToken))
		})
	})
})
