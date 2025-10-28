package validation

import (
	"bytes"
	"gateway/internal/config"
	"gateway/internal/server/auth"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type reqTestCase struct {
	name           string
	requestBody    string
	endpoint       string
	expectedStatus int
}

func TestMain(m *testing.M) {

	gin.SetMode(gin.ReleaseMode)
	os.Exit(m.Run())
}

func TestValidator_Positive(t *testing.T) {

	goodRequestRegisterBody := `{
    "email": "leo.urin@example.com",
    "password": "superpassword",
    "phone": "+79999999999",
    "name": "Leo",
    "surname": "Urin",
    "fathers_name": "Olegivich",
    "birth_date": "1993-03-03"
}`

	RegisterCustomValidators()

	fakeAuth := httptest.NewServer(http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {

		wr.Header().Set("Content-Type", "application/json")
		wr.WriteHeader(http.StatusOK)
		_, _ = wr.Write([]byte(`{
				"access_token":"fake-access-token",
				"refresh_token":"fake-refresh-token",
				"user_id":1
			}`))
	}))
	defer fakeAuth.Close()

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: fakeAuth.URL,
		},
	}

	router := gin.New()
	auth.RegisterRoutes(testCfg, router.Group("/api/auth"), zap.NewNop())

	cases := []reqTestCase{
		{
			name:           "valid login request body",
			requestBody:    `{"email":"test1@example.com","password":"password1"}`,
			endpoint:       "/api/auth/login",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "valid register request body",
			requestBody:    goodRequestRegisterBody,
			endpoint:       "/api/auth/register",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			// t.Parallel()

			wr := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(wr)

			req := httptest.NewRequest(
				http.MethodPost, tc.endpoint, bytes.NewBufferString(tc.requestBody))
			req.Header.Set("Content-Type", "application/json")
			c.Request = req

			handler := auth.NewHandler(testCfg, zap.NewNop())

			if strings.Contains(tc.endpoint, "register") {
				handler.Register(c)
				require.Equal(t, tc.expectedStatus, wr.Code)
				assert.NotEmpty(t, wr.Body.String())
			}

			if strings.Contains(tc.endpoint, "login") {
				handler.Login(c)
				require.Equal(t, tc.expectedStatus, wr.Code)
				assert.NotEmpty(t, wr.Body.String())
			}
		})
	}
}

func TestValidator_Negative(t *testing.T) {

	registerBodyBadPhone := `{
    "email": "leo.urin@example.com",
    "password": "superpassword",
    "phone": "+7-999-999-99-99",
    "name": "Leo",
    "surname": "Urin",
    "fathers_name": "Olegivich",
    "birth_date": "1993-03-03"
}`
	registerBodyBadName := `{
    "email": "leo.urin@example.com",
    "password": "superpassword",
    "phone": "+79999999999",
    "name": "1234",
    "surname": "Urin",
    "fathers_name": "Olegivich",
    "birth_date": "1993-03-03"
}`
	registerBodyBadSurname := `{
    "email": "leo.urin@example.com",
    "password": "superpassword",
    "phone": "+79999999999",
    "name": "Leo",
    "surname": "1234",
    "fathers_name": "Olegivich",
    "birth_date": "1993-03-03"
}`
	registerBodyBadFathersName := `{
    "email": "leo.urin@example.com",
    "password": "superpassword",
    "phone": "+79999999999",
    "name": "Leo",
    "surname": "Urin",
    "fathers_name": "1234",
    "birth_date": "1993-03-03"
}`
	registerBodyBadBirthDate := `{
    "email": "leo.urin@example.com",
    "password": "superpassword",
    "phone": "+79999999999",
    "name": "Leo",
    "surname": "Urin",
    "fathers_name": "Olegivich",
    "birth_date": "03-03-1993"
}`

	RegisterCustomValidators()

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: "http://auth-service:7971",
		},
	}

	router := gin.New()
	auth.RegisterRoutes(testCfg, router.Group("/api/auth"), zap.NewNop())
	handler := auth.NewHandler(testCfg, zap.NewNop())

	cases := []reqTestCase{
		{
			name:           "invalid phone in register request body",
			requestBody:    registerBodyBadPhone,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid name in register request body",
			requestBody:    registerBodyBadName,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid surname in register request body",
			requestBody:    registerBodyBadSurname,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid father's name in register request body",
			requestBody:    registerBodyBadFathersName,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid birth date in register request body",
			requestBody:    registerBodyBadBirthDate,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			// t.Parallel()

			wr := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(wr)

			req := httptest.NewRequest(
				http.MethodPost, "/api/auth/register", bytes.NewBufferString(tc.requestBody))
			req.Header.Set("Content-Type", "application/json")
			c.Request = req

			handler.Register(c)

			require.Equal(t, tc.expectedStatus, wr.Code)
			assert.NotEmpty(t, wr.Body.String())
		})
	}
}
