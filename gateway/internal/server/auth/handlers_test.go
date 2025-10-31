package auth

import (
	"bytes"
	"encoding/json"
	"github.com/LevYur/project/gateway/internal/config"
	"github.com/LevYur/project/gateway/internal/validation"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

type reqTestCase struct {
	name           string
	requestBody    []byte
	authURL        string
	endpoint       string
	authMethod     string
	expectedStatus int
	expectedBody   string
}

type proxyTestCase struct {
	name           string
	authStatusCode int
	authBody       string
	authCT         string
	expectedStatus int
	expectedBody   string
	expectedCT     string
}

func TestMain(m *testing.M) {

	gin.SetMode(gin.ReleaseMode)
	os.Exit(m.Run())
}

// LOGIN UNIT-TESTS ===================================

func TestLoginHandler_Positive(t *testing.T) {

	reqBody := []byte(`{"email":"test1@example.com","password":"password1"}`)

	wr := httptest.NewRecorder()

	c, _ := gin.CreateTestContext(wr)

	fakeAuth := httptest.NewServer(
		http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {

			wr.WriteHeader(http.StatusOK)
			_, _ = wr.Write([]byte(`{
				"access_token":"fake-access-token",
				"refresh_token":"fake-refresh-token",
				"user_id":1
			}`))
		}))
	defer fakeAuth.Close()

	req, _ := http.NewRequest(http.MethodPost, fakeAuth.URL, bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: fakeAuth.URL,
		},
		HTTPServer: config.HTTPServer{
			Timeout:     3 * time.Second,
			IdleTimeout: 60 * time.Second,
		},
	}

	handler := NewHandler(testCfg, zap.NewNop())
	handler.Login(c)

	require.Equal(t, http.StatusOK, wr.Code)

	bodyBytes, err := io.ReadAll(wr.Body)
	require.NoError(t, err)

	var resp LoginResponse
	err = json.Unmarshal(bodyBytes, &resp)
	require.NoError(t, err)

	require.NotEmpty(t, resp.AccessToken)
	require.NotEmpty(t, resp.RefreshToken)
	require.NotZero(t, resp.UserID)
}

func TestLoginHandler_Negative(t *testing.T) {

	cases := []reqTestCase{
		{
			name:           "invalid JSON empty body",
			requestBody:    nil, // error []byte(`{""}`),
			endpoint:       "/api/auth/login",
			authMethod:     http.MethodPost,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid JSON: bad email",
			requestBody:    []byte(`{"email":"test1example.com", "password":"password1"}`), // error
			endpoint:       "/api/auth/login",
			authMethod:     http.MethodPost,
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
				tc.authMethod, tc.endpoint, bytes.NewBuffer(tc.requestBody))

			req.Header.Set("Content-Type", "application/json")
			c.Request = req

			testCfg := &config.Config{
				Services: config.Services{
					AuthServiceAddr: "http://auth-service:7971",
				},
			}

			handler := NewHandler(testCfg, zap.NewNop())
			handler.Login(c)

			require.Equal(t, tc.expectedStatus, wr.Code)
		})
	}
}

func TestLoginHandler_Proxy_Negative(t *testing.T) {

	cases := []proxyTestCase{
		{
			name:           "auth service returns 401",
			authCT:         "application/json; charset=utf-8",
			authStatusCode: http.StatusUnauthorized,
			authBody:       `{"error":"invalid credentials"}`,
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   `{"error":"invalid credentials"}`,
			expectedCT:     "application/json; charset=utf-8",
		},
		{
			name:           "auth service returns 400",
			authCT:         "application/json; charset=utf-8",
			authStatusCode: http.StatusBadRequest,
			authBody:       `{"error":"invalid request"}`,
			expectedStatus: http.StatusBadRequest,
			expectedBody:   `{"error":"invalid request"}`,
			expectedCT:     "application/json; charset=utf-8",
		},
		{
			name:           "auth service returns 500",
			authCT:         "application/json; charset=utf-8",
			authStatusCode: http.StatusInternalServerError,
			authBody:       `{"error":"internal server error"}`,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   `{"error":"internal server error"}`,
			expectedCT:     "application/json; charset=utf-8",
		},
		{
			name:           "auth service returns 404",
			authCT:         "application/json; charset=utf-8",
			authStatusCode: http.StatusNotFound,
			authBody:       `{"error":"user not found"}`,
			expectedStatus: http.StatusNotFound,
			expectedBody:   `{"error":"user not found"}`,
			expectedCT:     "application/json; charset=utf-8",
		},
		{
			name:           "auth service returns 400 with text/plain",
			authCT:         "text/plain",
			authStatusCode: http.StatusBadRequest,
			authBody:       "bad request plain text",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "bad request plain text",
			expectedCT:     "text/plain",
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			t.Parallel()

			fakeAuth := httptest.NewServer(
				http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {

					wr.Header().Set("Content-Type", tc.authCT)
					wr.WriteHeader(tc.authStatusCode)
					_, _ = wr.Write([]byte(tc.authBody))
				}))
			defer fakeAuth.Close()

			reqBody := []byte(`{"email":"test2@example.com","password":"password2"}`)
			req := httptest.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")

			wr := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(wr)
			c.Request = req

			testCfg := &config.Config{
				Services: config.Services{
					AuthServiceAddr: fakeAuth.URL,
				},
				HTTPServer: config.HTTPServer{
					Timeout:     3 * time.Second,
					IdleTimeout: 60 * time.Second,
				},
			}

			handler := NewHandler(testCfg, zap.NewNop())

			handler.Login(c)

			require.Equal(t, tc.expectedStatus, wr.Code)
			require.Equal(t, tc.expectedCT, wr.Header().Get("Content-Type"))

			if tc.expectedCT == "application/json; charset=utf-8" {
				require.JSONEq(t, tc.expectedBody, wr.Body.String())
			} else {
				require.Equal(t, tc.expectedBody, wr.Body.String())
			}
		})
	}
}

func TestLoginHandler_URL_Negative(t *testing.T) {

	cases := []reqTestCase{
		{
			name:           "invalid syntax of URL (500)",
			authURL:        "://invalid-url", // error
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   `{"error":"internal server error"}`,
		},
		{
			name:           "unavailable service (502)",
			authURL:        "http://127.0.0.1:9999", // error
			expectedStatus: http.StatusBadGateway,
			expectedBody:   `{"error":"auth service unavailable"}`,
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			reqBody := []byte(`{"email":"test4@example.com","password":"password4"}`)
			wr := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(wr)

			req, _ := http.NewRequest(
				http.MethodPost, "/api/auth/login", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")
			c.Request = req

			testCfg := &config.Config{
				Services: config.Services{
					AuthServiceAddr: tc.authURL,
				},
				HTTPServer: config.HTTPServer{
					Timeout:     3 * time.Second,
					IdleTimeout: 60 * time.Second,
				},
			}

			handler := NewHandler(testCfg, zap.NewNop())
			handler.Login(c)

			require.Equal(t, tc.expectedStatus, wr.Code)
			require.Equal(t, "application/json; charset=utf-8", wr.Header().Get("Content-Type"))
			require.JSONEq(t, tc.expectedBody, wr.Body.String())
		})
	}
}

// REGISTER UNIT-TESTS ===================================

func TestRegisterHandler_Positive(t *testing.T) {

	reqBody := []byte(`{
    "email": "leo.urin@example.com",
    "password": "superpassword",
    "phone": "+79999999999",
    "name": "Leo",
    "surname": "Urin",
    "fathers_name": "Olegivich",
    "birth_date": "1993-03-03"
}`)

	wr := httptest.NewRecorder()

	c, _ := gin.CreateTestContext(wr)

	fakeAuth := httptest.NewServer(
		http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {

			wr.WriteHeader(http.StatusOK)
			_, _ = wr.Write([]byte(`{
				"access_token":"fake-access-token",
				"refresh_token":"fake-refresh-token",
				"user_id":1
			}`))
		}))
	defer fakeAuth.Close()

	req, _ := http.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: fakeAuth.URL,
		},
		HTTPServer: config.HTTPServer{
			Timeout:     3 * time.Second,
			IdleTimeout: 60 * time.Second,
		},
	}

	handler := NewHandler(testCfg, zap.NewNop())
	validation.RegisterCustomValidators()
	handler.Register(c)

	require.Equal(t, http.StatusOK, wr.Code)

	bodyBytes, err := io.ReadAll(wr.Body)
	require.NoError(t, err)

	var resp RegisterResponse
	err = json.Unmarshal(bodyBytes, &resp)
	require.NoError(t, err)

	require.NotEmpty(t, resp.AccessToken)
	require.NotEmpty(t, resp.RefreshToken)
	require.NotZero(t, resp.UserID)
}

func TestRegisterHandler_Negative(t *testing.T) {

	badReqBody := []byte(`{
    "email": "leo.urin.example.com",
    "password": "",
    "phone": "+7-999-999-99-99",
    "name": "Leo",
    "surname": "Urin",
    "fathers_name": "Olegivich",
    "birth_date": "1993-03-03"
}`)

	cases := []reqTestCase{
		{
			name:           "invalid JSON empty body",
			requestBody:    nil, // error []byte(`{}`),
			endpoint:       "/api/auth/register",
			authMethod:     http.MethodPost,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid JSON: bad email",
			requestBody:    badReqBody, // error
			endpoint:       "/api/auth/register",
			authMethod:     http.MethodPost,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			t.Parallel()

			wr := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(wr)

			req, err := http.NewRequest(
				tc.authMethod, tc.endpoint, bytes.NewBuffer(tc.requestBody))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			c.Request = req

			testCfg := &config.Config{
				Services: config.Services{
					AuthServiceAddr: "http://auth-service:7971",
				},
				HTTPServer: config.HTTPServer{
					Timeout:     3 * time.Second,
					IdleTimeout: 60 * time.Second,
				},
			}

			handler := NewHandler(testCfg, zap.NewNop())
			validation.RegisterCustomValidators()
			handler.Register(c)

			require.Equal(t, tc.expectedStatus, wr.Code)
		})
	}
}

func TestRegisterHandler_Proxy_Negative(t *testing.T) {

	cases := []proxyTestCase{
		{
			name:           "auth service returns 409",
			authCT:         "application/json; charset=utf-8",
			authStatusCode: http.StatusConflict,
			authBody:       `{"error":"user already registered"}`,
			expectedStatus: http.StatusConflict,
			expectedBody:   `{"error":"user already registered"}`,
			expectedCT:     "application/json; charset=utf-8",
		},
		{
			name:           "auth service returns 500",
			authCT:         "application/json; charset=utf-8",
			authStatusCode: http.StatusInternalServerError,
			authBody:       `{"error":"internal server error"}`,
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   `{"error":"internal server error"}`,
			expectedCT:     "application/json; charset=utf-8",
		},
		{
			name:           "auth service returns 404",
			authCT:         "application/json; charset=utf-8",
			authStatusCode: http.StatusNotFound,
			authBody:       `{"error":"user not found"}`,
			expectedStatus: http.StatusNotFound,
			expectedBody:   `{"error":"user not found"}`,
			expectedCT:     "application/json; charset=utf-8",
		},
		{
			name:           "auth service returns 400 with text/plain",
			authCT:         "text/plain",
			authStatusCode: http.StatusBadRequest,
			authBody:       "bad request plain text",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "bad request plain text",
			expectedCT:     "text/plain",
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			t.Parallel()

			fakeAuth := httptest.NewServer(
				http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {

					wr.Header().Set("Content-Type", tc.authCT)
					wr.WriteHeader(tc.authStatusCode)
					_, _ = wr.Write([]byte(tc.authBody))
				}))
			defer fakeAuth.Close()

			reqBody := []byte(`{
    "email": "leo.urin@example.com",
    "password": "superpassword",
    "phone": "+79999999999",
    "name": "Leo",
    "surname": "Urin",
    "fathers_name": "Olegivich",
    "birth_date": "1993-03-03"
}`)
			req, _ := http.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")

			wr := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(wr)
			c.Request = req

			testCfg := &config.Config{
				Services: config.Services{
					AuthServiceAddr: fakeAuth.URL,
				},
				HTTPServer: config.HTTPServer{
					Timeout:     3 * time.Second,
					IdleTimeout: 60 * time.Second,
				},
			}

			handler := NewHandler(testCfg, zap.NewNop())
			validation.RegisterCustomValidators()
			handler.Register(c)

			require.Equal(t, tc.expectedStatus, wr.Code)
			require.Equal(t, tc.expectedCT, wr.Header().Get("Content-Type"))

			if tc.expectedCT == "application/json; charset=utf-8" {
				require.JSONEq(t, tc.expectedBody, wr.Body.String())
			} else {
				require.Equal(t, tc.expectedBody, wr.Body.String())
			}
		})
	}
}

func TestRegisterHandler_URL_Negative(t *testing.T) {

	cases := []reqTestCase{
		{
			name:           "invalid syntax of URL (500)",
			authURL:        "://invalid-url", // error
			expectedStatus: http.StatusInternalServerError,
			expectedBody:   `{"error":"internal server error"}`,
		},
		{
			name:           "unavailable service (502)",
			authURL:        "http://127.0.0.1:9999", // error
			expectedStatus: http.StatusBadGateway,
			expectedBody:   `{"error":"auth service unavailable"}`,
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			reqBody := []byte(`{
    "email": "leo.urin@example.com",
    "password": "superpassword",
    "phone": "+79999999999",
    "name": "Leo",
    "surname": "Urin",
    "fathers_name": "Olegivich",
    "birth_date": "1993-03-03"
}`)

			wr := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(wr)

			req, _ := http.NewRequest(
				http.MethodPost, "/api/auth/register", bytes.NewBuffer(reqBody))
			req.Header.Set("Content-Type", "application/json")

			c.Request = req

			testCfg := &config.Config{
				Services: config.Services{
					AuthServiceAddr: tc.authURL,
				},
				HTTPServer: config.HTTPServer{
					Timeout:     3 * time.Second,
					IdleTimeout: 60 * time.Second,
				},
			}

			handler := NewHandler(testCfg, zap.NewNop())
			validation.RegisterCustomValidators()
			handler.Register(c)

			require.Equal(t, tc.expectedStatus, wr.Code)
			require.Equal(t, "application/json; charset=utf-8", wr.Header().Get("Content-Type"))
			require.JSONEq(t, tc.expectedBody, wr.Body.String())
		})
	}
}
