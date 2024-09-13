package verify_test

import (
	"testing"

	"github.com/mummumgoodboy/verify"
)

func TestJWTVerify(t *testing.T) {
	token := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1c2VyLW1hbmFnZW1lbnQtc2VydmljZSIsInN1YiI6InBrcHQiLCJleHAiOjE3MjYzMjM0OTIsImlhdCI6MTcyNjIzNzA5MiwidXNlcklkIjoxLCJpc0FkbWluIjpmYWxzZX0.AsTUq3u1uqQdxlyovDScr4RCMo2Gkx_4Abcp1h7Yb88vGIf9BLJ-k35mDSsIIV1Dv264h4O7c8pox8BCDRWuDA"
	key := `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAX8kTcJQhr9pFNISj3uSPVsJ3Pnq/he9iGJa64fHfWzk=
-----END PUBLIC KEY-----`

	verifier, err := verify.NewJWTVerifier(key)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := verifier.Verify(token)
	if err != nil {
		t.Fatal(err)
	}

	if claims.UserId != 1 {
		t.Fatalf("expected user id to be 1, got %d", claims.UserId)
	}

	if claims.IsAdmin {
		t.Fatalf("expected user to not be an admin")
	}

	if claims.Issuer != "user-management-service" {
		t.Fatalf("expected issuer to be user-management-service, got %s", claims.Issuer)
	}

	if claims.Subject != "pkpt" {
		t.Fatalf("expected subject to be pkpt, got %s", claims.Subject)
	}
}
