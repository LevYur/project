package integration

import (
	"bytes"
	"encoding/json"
	"gateway/internal/config"
	"gateway/internal/middleware"
	"gateway/internal/server/auth"
	"gateway/internal/validation"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestMain(m *testing.M) {

	gin.SetMode(gin.ReleaseMode)
	os.Exit(m.Run())
}

func TestGatewayIntegration(t *testing.T) {

	goodRespBody := `{
				"access_token":"fake-access-token",
				"refresh_token":"fake-refresh-token",
				"user_id":1
			}`

	fakeAuth := httptest.NewServer(
		http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {

			switch req.URL.Path {
			case "/auth/login":

				wr.Header().Set("Content-Type", "application/json")
				wr.WriteHeader(http.StatusOK)
				_, _ = wr.Write([]byte(goodRespBody))

			case "/auth/register":
				wr.Header().Set("Content-Type", "application/json")
				wr.WriteHeader(http.StatusOK)
				_, _ = wr.Write([]byte(goodRespBody))
			default:
				wr.WriteHeader(http.StatusNotFound)
			} // login and register path's
		}))
	defer fakeAuth.Close()

	gin.SetMode(gin.TestMode)

	router := gin.New()

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: fakeAuth.URL,
		},
	}

	auth.RegisterRoutes(testCfg, router.Group("/api/auth"), zap.NewNop())

	goodRegisterReqBody := `{
    "email": "leo.urin@example.com",
    "password": "superpassword",
    "phone": "+79999999999",
    "name": "Leo",
    "surname": "Urin",
    "fathers_name": "Olegivich",
    "birth_date": "1993-03-03"
}`

	cases := []struct {
		name           string
		endpoint       string
		method         string
		reqBody        string
		expectedStatus int
	}{
		{
			name:           "login success",
			endpoint:       "/api/auth/login",
			method:         http.MethodPost,
			reqBody:        `{"email":"test1@example.com","password":"password1"}`,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "register success",
			endpoint:       "/api/auth/register",
			method:         http.MethodPost,
			reqBody:        goodRegisterReqBody,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			req := httptest.NewRequest(tc.method, tc.endpoint, bytes.NewBufferString(tc.reqBody))
			req.Header.Set("Content-Type", "application/json")

			wr := httptest.NewRecorder()
			router.ServeHTTP(wr, req) // передаёт запрос в router

			require.Equal(t, tc.expectedStatus, wr.Code)

			var resp struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
				UserID       int    `json:"user_id"`
			}

			validation.RegisterCustomValidators()

			err := json.Unmarshal(wr.Body.Bytes(), &resp)
			require.NoError(t, err)
			require.NotEmpty(t, resp.AccessToken)
			require.NotEmpty(t, resp.RefreshToken)
			require.NotZero(t, resp.UserID)
		})
	}
}

func TestGatewayIntegration_InvalidURL_Negative(t *testing.T) {

	gin.SetMode(gin.TestMode)

	cases := []struct {
		name           string
		authServiceURL string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "invalid syntax of URL (500)",
			authServiceURL: "://invalid-url", // error
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   `{"error":"internal server error"}`,
		},
		{
			name:           "unavailable service (502)",
			authServiceURL: "http://127.0.0.1:9999", // error
			expectedStatus: http.StatusBadGateway,
			expectedBody:   `{"error":"auth service unavailable"}`,
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			testCfg := &config.Config{
				Services: config.Services{
					AuthServiceAddr: tc.authServiceURL, // invalid auth-service addr
				},
			}

			router := gin.New()
			router.Use(middleware.Recoverer(zap.NewNop()))

			auth.RegisterRoutes(testCfg, router.Group("/api/auth"), zap.NewNop())

			reqBody := bytes.NewBufferString(`{"email":"test1@example.com","password":"password1"}`)
			req := httptest.NewRequest(http.MethodPost, "/api/auth/login", reqBody)
			req.Header.Set("Content-Type", "application/json")

			wr := httptest.NewRecorder()
			router.ServeHTTP(wr, req) // передаёт запрос в router

			require.Equal(t, tc.expectedStatus, wr.Code)
			require.JSONEq(t, tc.expectedBody, wr.Body.String())
		})
	}
}

func TestGatewayIntegration_Proxy_Negative(t *testing.T) {

	timeout := 5 * time.Second

	goodLoginReq := `{"email":"test3@example.com","password":"password3"}`
	goodRegisterReq := `{
    "email": "leo.urin@example.com",
    "password": "superpassword",
    "phone": "+79999999999",
    "name": "Leo",
    "surname": "Urin",
    "fathers_name": "Olegivich",
    "birth_date": "1993-03-03"
}`
	badAuthResponse := `{"token": "abc123"`

	cases := []struct {
		name                    string
		endpoint                string
		request                 string
		authStatusCode          int
		authCT                  string
		authBody                string
		expectedStatus          int
		expectedCT              string
		expectedBody            string
		authTimeout             time.Duration
		authCustomKeyHeader     string
		expectedCustomKeyHeader string
		authValueHeader         string
		expectedValueHeader     string
	}{
		{
			name:           "auth service returns 401",
			endpoint:       "/api/auth/login",
			request:        goodLoginReq,
			authCT:         "application/json; charset=utf-8",
			authStatusCode: http.StatusUnauthorized,
			expectedStatus: http.StatusUnauthorized,
			expectedCT:     "application/json; charset=utf-8",
		},
		{
			name:           "auth service login returns 400",
			endpoint:       "/api/auth/login",
			request:        goodLoginReq,
			authCT:         "application/json; charset=utf-8",
			authStatusCode: http.StatusBadRequest,
			expectedStatus: http.StatusBadRequest,
			expectedCT:     "application/json; charset=utf-8",
		},
		{
			name:           "auth service register returns 400",
			endpoint:       "/api/auth/register",
			request:        goodRegisterReq,
			authCT:         "application/json; charset=utf-8",
			authStatusCode: http.StatusBadRequest,
			expectedStatus: http.StatusBadRequest,
			expectedCT:     "application/json; charset=utf-8",
		},
		{
			name:           "auth service login returns 500",
			endpoint:       "/api/auth/login",
			request:        goodLoginReq,
			authCT:         "application/json; charset=utf-8",
			authStatusCode: http.StatusInternalServerError,
			expectedStatus: http.StatusInternalServerError,
			expectedCT:     "application/json; charset=utf-8",
		},
		{
			name:           "auth service register returns 500",
			endpoint:       "/api/auth/register",
			request:        goodRegisterReq,
			authCT:         "application/json; charset=utf-8",
			authStatusCode: http.StatusInternalServerError,
			expectedStatus: http.StatusInternalServerError,
			expectedCT:     "application/json; charset=utf-8",
		},
		{
			name:           "auth service returns 404",
			endpoint:       "/api/auth/login",
			request:        goodLoginReq,
			authCT:         "application/json; charset=utf-8",
			authStatusCode: http.StatusNotFound,
			expectedStatus: http.StatusNotFound,
			expectedCT:     "application/json; charset=utf-8",
		},
		{
			name:           "auth service returns non-JSON content type (text/plain)",
			endpoint:       "/api/auth/login",
			request:        goodLoginReq,
			authCT:         "text/plain",
			authStatusCode: http.StatusBadRequest,
			expectedStatus: http.StatusBadRequest,
			expectedCT:     "text/plain",
		},
		{
			name:           "auth service (login) returns 200",
			endpoint:       "/api/auth/login",
			request:        goodLoginReq,
			authCT:         "application/json; charset=utf-8",
			authStatusCode: http.StatusOK,
			expectedStatus: http.StatusOK,
			expectedCT:     "application/json; charset=utf-8",
			expectedBody:   badAuthResponse,
		},
		{
			name:           "auth service (register) returns 200",
			endpoint:       "/api/auth/register",
			request:        goodRegisterReq,
			authCT:         "application/json; charset=utf-8",
			authStatusCode: http.StatusOK,
			expectedStatus: http.StatusOK,
			expectedCT:     "application/json; charset=utf-8",
			expectedBody:   badAuthResponse,
		},
		{
			name:           "auth service (login) timeout returns 504",
			endpoint:       "/api/auth/login",
			request:        goodLoginReq,
			expectedStatus: http.StatusGatewayTimeout,
			expectedCT:     "application/json; charset=utf-8",
			expectedBody:   `{"error":"timeout"}`,
			authTimeout:    timeout + 1*time.Second, // error, timeout
		},
		{
			name:           "auth service (register) timeout returns 504",
			endpoint:       "/api/auth/register",
			request:        goodRegisterReq,
			expectedStatus: http.StatusGatewayTimeout,
			expectedCT:     "application/json; charset=utf-8",
			expectedBody:   `{"error":"timeout"}`,
			authTimeout:    timeout + 1*time.Second, // error, timeout
		},
		{
			name:                    "auth service (login) invalid key header returns 200",
			endpoint:                "/api/auth/login",
			request:                 goodLoginReq,
			authCT:                  "application/json; charset=utf-8",
			authCustomKeyHeader:     "X-Foo",
			authStatusCode:          http.StatusOK,
			expectedStatus:          http.StatusOK,
			expectedCT:              "application/json; charset=utf-8",
			expectedCustomKeyHeader: "X-Foo",
		},
		{
			name:                    "auth service (register) invalid key header returns 200",
			endpoint:                "/api/auth/register",
			request:                 goodRegisterReq,
			authCT:                  "application/json; charset=utf-8",
			authCustomKeyHeader:     "X-Foo",
			authStatusCode:          http.StatusOK,
			expectedStatus:          http.StatusOK,
			expectedCT:              "application/json; charset=utf-8",
			expectedCustomKeyHeader: "X-Foo",
		},
		{
			name:                "auth service (login) invalid length header returns 200",
			endpoint:            "/api/auth/login",
			request:             goodLoginReq,
			authCT:              "application/json; charset=utf-8",
			authValueHeader:     "-1",
			authStatusCode:      http.StatusOK,
			expectedStatus:      http.StatusOK,
			expectedCT:          "application/json; charset=utf-8",
			expectedValueHeader: "-1",
		},
		{
			name:                "auth service (register) invalid length header returns 200",
			endpoint:            "/api/auth/register",
			request:             goodRegisterReq,
			authCT:              "application/json; charset=utf-8",
			authValueHeader:     "-1",
			authStatusCode:      http.StatusOK,
			expectedStatus:      http.StatusOK,
			expectedCT:          "application/json; charset=utf-8",
			expectedValueHeader: "-1",
		},
		{
			name:                "auth service (login) invalid cookie header returns 200",
			endpoint:            "/api/auth/login",
			request:             goodLoginReq,
			authCT:              "application/json; charset=utf-8",
			authValueHeader:     "token==; Path=/",
			authStatusCode:      http.StatusOK,
			expectedStatus:      http.StatusOK,
			expectedCT:          "application/json; charset=utf-8",
			expectedValueHeader: "token==; Path=/",
		},
		{
			name:                "auth service (register) invalid cookie header returns 200",
			endpoint:            "/api/auth/register",
			request:             goodRegisterReq,
			authCT:              "application/json; charset=utf-8",
			authValueHeader:     "token==; Path=/",
			authStatusCode:      http.StatusOK,
			expectedStatus:      http.StatusOK,
			expectedCT:          "application/json; charset=utf-8",
			expectedValueHeader: "token==; Path=/",
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			t.Parallel()

			authServer := httptest.NewServer(
				http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {

					if tc.authTimeout > 0 {
						time.Sleep(tc.authTimeout)
						return
					}

					switch req.URL.Path {
					case "/auth/login":
						wr.Header().Set("Content-Type", tc.authCT)

						wr.Header().Add(tc.authCustomKeyHeader, tc.authCT)
						wr.Header().Add("Content-Length", tc.authValueHeader)
						wr.Header().Add("Set-Cookie", tc.authValueHeader)

						wr.WriteHeader(tc.authStatusCode)
						_, _ = wr.Write([]byte(tc.expectedBody))

					case "/auth/register":
						wr.Header().Set("Content-Type", tc.authCT)

						wr.Header().Set(tc.authCustomKeyHeader, tc.authCT)
						wr.Header().Set("Content-Length", tc.authValueHeader)
						wr.Header().Set("Set-Cookie", tc.authValueHeader)

						wr.WriteHeader(tc.authStatusCode)
						_, _ = wr.Write([]byte(tc.expectedBody))
					default:
						wr.WriteHeader(http.StatusNotFound)
					}
				}))
			defer authServer.Close()

			router := gin.New()
			router.Use(middleware.Recoverer(zap.NewNop()))
			router.Use(middleware.Timeout(timeout))

			testCfg := &config.Config{
				Services: config.Services{
					AuthServiceAddr: authServer.URL,
				},
				HTTPServer: config.HTTPServer{
					Timeout: timeout,
				},
			}

			auth.RegisterRoutes(testCfg, router.Group("/api/auth"), zap.NewNop())

			req := httptest.NewRequest(http.MethodPost, tc.endpoint, bytes.NewBufferString(tc.request))
			req.Header.Set("Content-Type", "application/json")

			wr := httptest.NewRecorder()

			router.ServeHTTP(wr, req)

			require.Equal(t, tc.expectedStatus, wr.Code)
			require.Equal(t, tc.expectedCT, wr.Header().Get("Content-Type"))

			if wr.Body.Len() > 0 {
				require.Equal(t, tc.expectedBody, wr.Body.String())
			}

			if wr.Header().Get(tc.authCustomKeyHeader) != "" {
				require.Equal(t, tc.expectedStatus, wr.Code)
			}

			if wr.Header().Get("Content-Length") != "" {
				require.Equal(t, tc.expectedStatus, wr.Code)
			}

			if wr.Header().Get("Set-Cookie") != "" {
				require.Equal(t, tc.expectedStatus, wr.Code)
			}

		})
	}
}

func TestGatewayIntegration_Negative(t *testing.T) {

	goodLoginReqBody := `{"email":"test1@example.com", "password":"password1"}`
	goodRegisterReqBody := `{
    "email": "leo.urin@example.com",
    "password": "superpassword",
    "phone": "+79999999999",
    "name": "Leo",
    "surname": "Urin",
    "fathers_name": "Olegivich",
    "birth_date": "1993-03-03"
}`

	cases := []struct {
		name           string
		endpoint       string
		requestMethod  string
		requestBody    string
		contentType    string
		expectedStatus int
		expectedCT     string
	}{
		{
			name:           "invalid method in login request returns 405",
			endpoint:       "/api/auth/login",
			requestMethod:  http.MethodGet, // error
			requestBody:    goodLoginReqBody,
			contentType:    "application/json; charset=utf-8",
			expectedStatus: http.StatusNotFound,
			expectedCT:     "application/json; charset=utf-8",
		},
		{
			name:           "invalid method in register request returns 405",
			endpoint:       "/api/auth/register",
			requestMethod:  http.MethodGet, // error
			requestBody:    goodRegisterReqBody,
			contentType:    "application/json; charset=utf-8",
			expectedStatus: http.StatusNotFound,
			expectedCT:     "application/json; charset=utf-8",
		},
		{
			name:           "invalid JSON in login request returns 400",
			endpoint:       "/api/auth/login",
			requestMethod:  http.MethodPost,
			requestBody:    `{"email": "invalid`, // error
			contentType:    "application/json; charset=utf-8",
			expectedStatus: http.StatusBadRequest,
			expectedCT:     "application/json; charset=utf-8",
		},
		{
			name:           "empty body in register request returns 400",
			endpoint:       "/api/auth/register",
			requestMethod:  http.MethodPost,
			requestBody:    "{}", // error
			contentType:    "application/json; charset=utf-8",
			expectedStatus: http.StatusBadRequest,
			expectedCT:     "application/json; charset=utf-8",
		},
	}

	for _, tc := range cases {

		t.Run(tc.name, func(t *testing.T) {

			req := httptest.NewRequest(tc.requestMethod, tc.endpoint, bytes.NewBufferString(tc.requestBody))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}

			wr := httptest.NewRecorder()

			router := gin.New()
			router.Use(middleware.Recoverer(zap.NewNop()))

			router.HandleMethodNotAllowed = true // для замены стандартных текстовых заголовков при 404

			router.NoRoute(func(c *gin.Context) {
				c.JSON(http.StatusNotFound, gin.H{"error": "route not found"})
			})

			router.NoMethod(func(c *gin.Context) {
				c.JSON(http.StatusNotFound, gin.H{"error": "method not allowed"})
			})

			testCfg := &config.Config{
				Services: config.Services{
					AuthServiceAddr: "http://auth-service:7971",
				},
			}

			auth.RegisterRoutes(testCfg, router.Group("/api/auth"), zap.NewNop())

			validation.RegisterCustomValidators()
			router.ServeHTTP(wr, req)

			require.Equal(t, tc.expectedStatus, wr.Code)
			require.Equal(t, tc.expectedCT, wr.Header().Get("Content-Type"))
		})
	}
}
