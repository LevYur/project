package integration

import (
	"bytes"
	"context"
	"gateway/internal/config"
	"gateway/internal/middleware"
	"gateway/internal/validation"
	"gateway/pkg/constants"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestRecoverMiddleware_Positive_Integration(t *testing.T) {

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

			case "/auth/refresh":
				wr.Header().Set("Content-Type", "application/json")
				wr.WriteHeader(http.StatusOK)
				_, _ = wr.Write([]byte(goodRespBody))

			default:
				wr.WriteHeader(http.StatusNotFound)
			} // login and register path's
		}))
	defer fakeAuth.Close()

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: fakeAuth.URL,
		},
	}

	validation.RegisterCustomValidators()

	router := gin.New()

	router.Use(middleware.Recoverer(zap.NewNop()))
	router.Use(middleware.Timeout(testCfg.Timeout))
	router.Use(middleware.ValidateContentType(zap.NewNop()))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(zap.NewNop()))
	router.Use(middleware.Cors())

	// validate and refresh tokens
	router.Use(middleware.AuthGuard(testCfg, zap.NewNop()))

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
		path           string
		reqBody        string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "valid request to auth/login",
			path:           "/auth/login",
			reqBody:        `{"email":"test1@example.com","password":"password1"}`,
			expectedStatus: http.StatusOK,
			expectedBody:   goodRespBody,
		},
		{
			name:           "valid request to auth/register",
			path:           "/auth/register",
			reqBody:        goodRegisterReqBody,
			expectedStatus: http.StatusOK,
			expectedBody:   goodRespBody,
		},
		{
			name:           "valid request to auth/refresh",
			path:           "/auth/refresh",
			expectedStatus: http.StatusOK,
			expectedBody:   goodRespBody,
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			router.POST(tc.path, func(c *gin.Context) {
				c.String(http.StatusOK, goodRespBody)
			})

			wr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tc.path, bytes.NewBufferString(tc.reqBody))
			req.Header.Set("Content-Type", "application/json")

			if tc.path == "/auth/refresh" {

				req.Header.Set("Authorization", "Bearer invalid_access_token")
				cookie := &http.Cookie{
					Name:  "refresh_token",
					Value: "any_refresh_token",
				}
				req.AddCookie(cookie)
			}

			router.ServeHTTP(wr, req)

			require.Equal(t, http.StatusOK, wr.Code)
			assert.Equal(t, goodRespBody, wr.Body.String())
		})
	}
}

func TestRecoverMiddleware_Negative_Integration(t *testing.T) {

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: "",
		},
	}

	validation.RegisterCustomValidators()

	router := gin.New()

	router.Use(middleware.Recoverer(zap.NewNop()))
	router.Use(middleware.Timeout(testCfg.Timeout))
	router.Use(middleware.ValidateContentType(zap.NewNop()))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(zap.NewNop()))
	router.Use(middleware.Cors())

	cases := []struct {
		name           string
		path           string
		expectedStatus int
	}{
		{
			name:           "panic request to auth/login",
			path:           "/auth/login",
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "panic request to auth/register",
			path:           "/auth/register",
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "panic request to auth/refresh",
			path:           "/auth/refresh",
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			router.POST(tc.path, func(c *gin.Context) {
				panic("test panic")
			})

			wr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req.Header.Set("Content-Type", "application/json")

			if tc.path == "/auth/refresh" {

				req.Header.Set("Authorization", "Bearer invalid_access_token")
				cookie := &http.Cookie{
					Name:  "refresh_token",
					Value: "any_refresh_token",
				}
				req.AddCookie(cookie)
			}

			router.ServeHTTP(wr, req)

			require.Equal(t, http.StatusInternalServerError, wr.Code, "expected 500 internal server error when panic occurs")
			assert.Contains(t, wr.Body.String(), "internal server error")
		})
	}
}

func TestTimeoutMiddleware_Positive_Integration(t *testing.T) {

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

			case "/auth/refresh":
				wr.Header().Set("Content-Type", "application/json")
				wr.WriteHeader(http.StatusOK)
				_, _ = wr.Write([]byte(goodRespBody))

			default:
				wr.WriteHeader(http.StatusNotFound)
			} // login and register path's
		}))
	defer fakeAuth.Close()

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: fakeAuth.URL,
		},
		HTTPServer: config.HTTPServer{
			Timeout: 2 * time.Second,
		},
	}

	validation.RegisterCustomValidators()

	router := gin.New()

	router.Use(middleware.Recoverer(zap.NewNop()))
	router.Use(middleware.Timeout(testCfg.Timeout))
	router.Use(middleware.ValidateContentType(zap.NewNop()))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(zap.NewNop()))
	router.Use(middleware.Cors())

	// validate and refresh tokens
	router.Use(middleware.AuthGuard(testCfg, zap.NewNop()))

	cases := []struct {
		name           string
		path           string
		expectedStatus int
	}{
		{
			name:           "request with context to auth/login",
			path:           "/auth/login",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with context to auth/register",
			path:           "/auth/register",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with context to auth/refresh",
			path:           "/auth/refresh",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			var hasDeadline bool

			router.POST(tc.path, func(c *gin.Context) {

				_, ok := c.Request.Context().Deadline()
				hasDeadline = ok
				c.String(http.StatusOK, goodRespBody)
			})

			wr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req.Header.Set("Content-Type", "application/json")

			router.ServeHTTP(wr, req)

			require.Equal(t, http.StatusOK, wr.Code)
			assert.True(t, hasDeadline, "context should have a deadline")
		})
	}
}

func TestValidateContentTypeMiddleware_Integration(t *testing.T) {

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

			case "/auth/refresh":
				wr.Header().Set("Content-Type", "application/json")
				wr.WriteHeader(http.StatusOK)
				_, _ = wr.Write([]byte(goodRespBody))

			default:
				wr.WriteHeader(http.StatusNotFound)
			}
		}))
	defer fakeAuth.Close()

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: fakeAuth.URL,
		},
		HTTPServer: config.HTTPServer{
			Timeout: 2 * time.Second,
		},
	}

	validation.RegisterCustomValidators()

	cases := []struct {
		name           string
		path           string
		contentType    string
		calledHandler  bool
		expectedStatus int
	}{
		{
			name:           "request with valid Content-Type to auth/login",
			path:           "/auth/login",
			contentType:    "application/json",
			calledHandler:  true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with valid Content-Type to auth/register",
			path:           "/auth/register",
			contentType:    "application/json",
			calledHandler:  true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with valid Content-Type to auth/refresh",
			path:           "/auth/refresh",
			contentType:    "application/json",
			calledHandler:  true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with empty Content-Type to auth/login",
			path:           "/auth/login",
			contentType:    "",
			calledHandler:  false,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "request with empty Content-Type to auth/register",
			path:           "/auth/register",
			contentType:    "",
			calledHandler:  false,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "request with empty Content-Type to auth/refresh",
			path:           "/auth/refresh",
			contentType:    "",
			calledHandler:  false,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "request with invalid Content-Type to auth/login",
			path:           "/auth/login",
			contentType:    "text/plain",
			calledHandler:  false,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "request with invalid Content-Type to auth/register",
			path:           "/auth/register",
			contentType:    "text/plain",
			calledHandler:  false,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "request with invalid Content-Type to auth/refresh",
			path:           "/auth/refresh",
			contentType:    "text/plain",
			calledHandler:  false,
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			router := gin.New()

			router.Use(middleware.Recoverer(zap.NewNop()))
			router.Use(middleware.Timeout(testCfg.Timeout))
			router.Use(middleware.ValidateContentType(zap.NewNop()))
			router.Use(middleware.RequestID())
			router.Use(middleware.Logger(zap.NewNop()))
			router.Use(middleware.Cors())

			// validate and refresh tokens
			router.Use(middleware.AuthGuard(testCfg, zap.NewNop()))

			called := false
			router.POST(tc.path, func(c *gin.Context) {

				called = true // меняется, если хендлер вызывается, но не всегда должен
				c.String(http.StatusOK, goodRespBody)
			})

			wr := httptest.NewRecorder()

			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req.Header.Set("Content-Type", tc.contentType)

			router.ServeHTTP(wr, req)

			require.Equal(t, tc.expectedStatus, wr.Code)
			assert.Equal(t, tc.calledHandler, called)
		})
	}
}

func TestRequestIDMiddleware_Positive_Integration(t *testing.T) {

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

			case "/auth/refresh":
				wr.Header().Set("Content-Type", "application/json")
				wr.WriteHeader(http.StatusOK)
				_, _ = wr.Write([]byte(goodRespBody))

			default:
				wr.WriteHeader(http.StatusNotFound)
			}
		}))
	defer fakeAuth.Close()

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: fakeAuth.URL,
		},
		HTTPServer: config.HTTPServer{
			Timeout: 2 * time.Second,
		},
	}

	validation.RegisterCustomValidators()

	cases := []struct {
		name           string
		path           string
		expectedStatus int
	}{
		{
			name:           "request with X-Request-ID to auth/login",
			path:           "/auth/login",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with X-Request-ID to auth/register",
			path:           "/auth/register",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with X-Request-ID to auth/refresh",
			path:           "/auth/refresh",
			expectedStatus: http.StatusOK,
		},
	}

	randomRequestID := uuid.NewString()

	router := gin.New()

	router.Use(middleware.Recoverer(zap.NewNop()))
	router.Use(middleware.Timeout(testCfg.Timeout))
	router.Use(middleware.ValidateContentType(zap.NewNop()))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(zap.NewNop()))
	router.Use(middleware.Cors())

	// validate and refresh tokens
	router.Use(middleware.AuthGuard(testCfg, zap.NewNop()))

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			router.POST(tc.path, func(c *gin.Context) {

				reqID, exists := c.Get(constants.RequestIDKey)
				require.True(t, exists)
				require.Equal(t, randomRequestID, reqID)

				_, err := uuid.Parse(reqID.(string))
				require.NoError(t, err, "X-Request-ID should be valid UUID")

				c.String(http.StatusOK, goodRespBody)
			})

			wr := httptest.NewRecorder()

			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Add("X-Request-ID", randomRequestID)

			router.ServeHTTP(wr, req)

			require.Equal(t, tc.expectedStatus, wr.Code)
			require.Equal(t, randomRequestID, wr.Header().Get("X-Request-ID"))

			reqID := wr.Header().Get("X-Request-ID")
			require.NotEmpty(t, reqID)

			_, err := uuid.Parse(reqID)
			require.NoError(t, err, "X-Request-ID should be valid UUID")
		})
	}
}

func TestLoggerMiddleware_Positive_Integration(t *testing.T) {

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

			case "/auth/refresh":
				wr.Header().Set("Content-Type", "application/json")
				wr.WriteHeader(http.StatusOK)
				_, _ = wr.Write([]byte(goodRespBody))

			default:
				wr.WriteHeader(http.StatusNotFound)
			}
		}))
	defer fakeAuth.Close()

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: fakeAuth.URL,
		},
		HTTPServer: config.HTTPServer{
			Timeout: 2 * time.Second,
		},
	}

	validation.RegisterCustomValidators()

	cases := []struct {
		name           string
		path           string
		expectedStatus int
	}{
		{
			name:           "request with enriched logger to auth/login",
			path:           "/auth/login",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with enriched logger to auth/register",
			path:           "/auth/register",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with enriched logger to auth/refresh",
			path:           "/auth/refresh",
			expectedStatus: http.StatusOK,
		},
	}

	router := gin.New()

	router.Use(middleware.Recoverer(zap.NewNop()))
	router.Use(middleware.Timeout(testCfg.Timeout))
	router.Use(middleware.ValidateContentType(zap.NewNop()))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(zap.NewNop()))
	router.Use(middleware.Cors())

	// validate and refresh tokens
	router.Use(middleware.AuthGuard(testCfg, zap.NewNop()))

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			router.POST(tc.path, func(c *gin.Context) {

				enrichedLogger, exists := c.Get(constants.LoggerKey)
				require.True(t, exists)

				_, ok := enrichedLogger.(*zap.Logger)
				require.True(t, ok)

				c.String(http.StatusOK, goodRespBody)
			})

			wr := httptest.NewRecorder()

			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req.Header.Set("Content-Type", "application/json")

			router.ServeHTTP(wr, req)

			require.Equal(t, tc.expectedStatus, wr.Code)

		})
	}
}

func TestCorsMiddleware_Positive_Integration(t *testing.T) {

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

			case "/auth/refresh":
				wr.Header().Set("Content-Type", "application/json")
				wr.WriteHeader(http.StatusOK)
				_, _ = wr.Write([]byte(goodRespBody))

			default:
				wr.WriteHeader(http.StatusNotFound)
			}
		}))
	defer fakeAuth.Close()

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: fakeAuth.URL,
		},
		HTTPServer: config.HTTPServer{
			Timeout: 2 * time.Second,
		},
	}

	validation.RegisterCustomValidators()

	cases := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
	}{
		{
			name:           "request with POST to auth/login",
			method:         http.MethodPost,
			path:           "/auth/login",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with GET to auth/login",
			method:         http.MethodGet,
			path:           "/auth/login",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with PUT to auth/login",
			method:         http.MethodPut,
			path:           "/auth/login",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with PATCH to auth/login",
			method:         http.MethodPatch,
			path:           "/auth/login",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with DELETE to auth/login",
			method:         http.MethodDelete,
			path:           "/auth/login",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with POST to auth/register",
			method:         http.MethodPost,
			path:           "/auth/register",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with GET to auth/register",
			method:         http.MethodGet,
			path:           "/auth/register",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with PUT to auth/register",
			method:         http.MethodPut,
			path:           "/auth/register",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with PATCH to auth/register",
			method:         http.MethodPatch,
			path:           "/auth/register",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with DELETE to auth/register",
			method:         http.MethodDelete,
			path:           "/auth/register",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with POST to auth/refresh",
			method:         http.MethodPost,
			path:           "/auth/refresh",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with GET to auth/refresh",
			method:         http.MethodGet,
			path:           "/auth/refresh",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with PUT to auth/refresh",
			method:         http.MethodPut,
			path:           "/auth/refresh",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with PATCH to auth/refresh",
			method:         http.MethodPatch,
			path:           "/auth/refresh",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with DELETE to auth/refresh",
			method:         http.MethodDelete,
			path:           "/auth/refresh",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "request with OPTIONS to auth/login",
			method:         http.MethodOptions,
			path:           "/auth/login",
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "request with OPTIONS to auth/register",
			method:         http.MethodOptions,
			path:           "/auth/register",
			expectedStatus: http.StatusNoContent,
		},
		{
			name:           "request with OPTIONS to auth/refresh",
			method:         http.MethodOptions,
			path:           "/auth/refresh",
			expectedStatus: http.StatusNoContent,
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			router := gin.New()

			router.Use(middleware.Recoverer(zap.NewNop()))
			router.Use(middleware.Timeout(testCfg.Timeout))
			router.Use(middleware.ValidateContentType(zap.NewNop()))
			router.Use(middleware.RequestID())
			router.Use(middleware.Logger(zap.NewNop()))
			router.Use(middleware.Cors())

			// validate and refresh tokens
			router.Use(middleware.AuthGuard(testCfg, zap.NewNop()))

			router.Any(tc.path, func(c *gin.Context) {
				c.String(http.StatusOK, goodRespBody)
			})

			wr := httptest.NewRecorder()

			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer token")

			router.ServeHTTP(wr, req)

			require.Equal(t, tc.expectedStatus, wr.Code)

			require.Equal(t, "*", wr.Header().Get("Access-Control-Allow-Origin"))
			require.Contains(t, wr.Header().Get("Access-Control-Allow-Methods"), "POST")
			require.Contains(t, wr.Header().Get("Access-Control-Allow-Headers"), "Authorization")
		})
	}
}

func TestRateLimiter_Positive_Integration(t *testing.T) {

	middleware.ResetVisitors() // обнулили данные карты в middleware

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

			case "/auth/refresh":
				wr.Header().Set("Content-Type", "application/json")
				wr.WriteHeader(http.StatusOK)
				_, _ = wr.Write([]byte(goodRespBody))

			default:
				wr.WriteHeader(http.StatusNotFound)
			}
		}))
	defer fakeAuth.Close()

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: fakeAuth.URL,
		},
		HTTPServer: config.HTTPServer{
			Timeout: 2 * time.Second,
		},
	}

	validation.RegisterCustomValidators()

	cases := []struct {
		name string
		path string
	}{
		{
			name: "request with IP to auth/login",
			path: "/auth/login",
		},
		{
			name: "request with IP to auth/register",
			path: "/auth/register",
		},
		{
			name: "request with IP to auth/refresh",
			path: "/auth/refresh",
		},
	}

	router := gin.New()

	router.Use(middleware.Recoverer(zap.NewNop()))
	router.Use(middleware.Timeout(testCfg.Timeout))
	router.Use(middleware.ValidateContentType(zap.NewNop()))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(zap.NewNop()))
	router.Use(middleware.Cors())
	router.Use(middleware.RateLimiter())

	// validate and refresh tokens
	router.Use(middleware.AuthGuard(testCfg, zap.NewNop()))

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			router.POST(tc.path, func(c *gin.Context) {
				c.String(http.StatusOK, goodRespBody)
			})

			wr := httptest.NewRecorder()

			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "192.168.1.1:1234" // ClientIP()

			router.ServeHTTP(wr, req)

			require.Equal(t, http.StatusOK, wr.Code)

		})
	}
}

func TestRateLimiter_Negative_Integration(t *testing.T) {

	middleware.ResetVisitors() // обнулили данные карты в middleware

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

			case "/auth/refresh":
				wr.Header().Set("Content-Type", "application/json")
				wr.WriteHeader(http.StatusOK)
				_, _ = wr.Write([]byte(goodRespBody))

			default:
				wr.WriteHeader(http.StatusNotFound)
			}
		}))
	defer fakeAuth.Close()

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: fakeAuth.URL,
		},
		HTTPServer: config.HTTPServer{
			Timeout: 2 * time.Second,
		},
	}

	validation.RegisterCustomValidators()

	cases := []struct {
		name string
		path string
	}{
		{
			name: "request with IP to auth/login",
			path: "/auth/login",
		},
		{
			name: "request with IP to auth/register",
			path: "/auth/register",
		},
		{
			name: "request with IP to auth/refresh",
			path: "/auth/refresh",
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			router := gin.New()

			router.Use(middleware.Recoverer(zap.NewNop()))
			router.Use(middleware.Timeout(testCfg.Timeout))
			router.Use(middleware.ValidateContentType(zap.NewNop()))
			router.Use(middleware.RequestID())
			router.Use(middleware.Logger(zap.NewNop()))
			router.Use(middleware.Cors())
			router.Use(middleware.RateLimiter())

			// validate and refresh tokens
			router.Use(middleware.AuthGuard(testCfg, zap.NewNop()))

			router.POST(tc.path, func(c *gin.Context) {
				c.String(http.StatusOK, goodRespBody)
			})

			wr := httptest.NewRecorder()

			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req.Header.Set("Content-Type", "application/json")
			req.RemoteAddr = "10.0.0.2:1234" // ClientIP()

			limiter := middleware.GetVisitor("10.0.0.2")
			for i := 0; i < 15; i++ { // Имитируем превышение лимита
				limiter.Allow()
			}

			router.ServeHTTP(wr, req)

			require.Equal(t, http.StatusTooManyRequests, wr.Code)

		})
	}
}

func TestAuthGuard_PublicRoutes_Positive_Integration(t *testing.T) {

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

			case "/auth/refresh":
				wr.Header().Set("Content-Type", "application/json")
				wr.WriteHeader(http.StatusOK)
				_, _ = wr.Write([]byte(goodRespBody))

			default:
				wr.WriteHeader(http.StatusNotFound)
			}
		}))
	defer fakeAuth.Close()

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: "",
		},
	}

	router := gin.New()

	router.Use(middleware.Recoverer(zap.NewNop()))
	router.Use(middleware.Timeout(testCfg.Timeout))
	router.Use(middleware.ValidateContentType(zap.NewNop()))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(zap.NewNop()))
	router.Use(middleware.Cors())
	router.Use(middleware.RateLimiter())

	// validate and refresh tokens
	router.Use(middleware.AuthGuard(testCfg, zap.NewNop()))

	cases := []struct {
		name string
		path string
	}{
		{
			name: "login path returns 200",
			path: "/api/auth/login",
		},
		{
			name: "register path returns 200",
			path: "/api/auth/register",
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			router.POST(tc.path, func(c *gin.Context) {
				c.String(http.StatusOK, goodRespBody)
			})

			wr := httptest.NewRecorder()

			req := httptest.NewRequest(http.MethodPost, tc.path, nil)
			req.Header.Set("Content-Type", "application/json")

			router.ServeHTTP(wr, req)

			require.Equal(t, http.StatusOK, wr.Code)
			assert.Contains(t, wr.Body.String(), "ok")
		})
	}
}

func TestAuthGuard_Private_ValidAccess_Positive_Integration(t *testing.T) {

	secret := "test_secret"
	userID := 1
	path := "/auth/refresh"

	goodRespBody := `{
				"access_token":"fake-access-token",
				"refresh_token":"fake-refresh-token",
				"user_id":1
			}`

	fakeAuth := httptest.NewServer(
		http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {

			wr.Header().Set("Content-Type", "application/json")
			wr.WriteHeader(http.StatusOK)
			_, _ = wr.Write([]byte(goodRespBody))

		}))
	defer fakeAuth.Close()

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: "",
		},
		Auth: config.Auth{
			JWTSecret: secret,
		},
	}

	router := gin.New()

	router.Use(middleware.Recoverer(zap.NewNop()))
	router.Use(middleware.Timeout(testCfg.Timeout))
	router.Use(middleware.ValidateContentType(zap.NewNop()))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(zap.NewNop()))
	router.Use(middleware.Cors())
	router.Use(middleware.RateLimiter())

	// validate and refresh tokens
	router.Use(middleware.AuthGuard(testCfg, zap.NewNop()))

	router.POST(path, func(c *gin.Context) {
		c.String(http.StatusOK, goodRespBody)
	})

	wr := httptest.NewRecorder()

	validAccessToken, _, err := generateTokens(userID, secret)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+validAccessToken)

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusOK, wr.Code)
	assert.Contains(t, wr.Body.String(), "ok")
}

func generateTokens(userID int, secret string) (accessToken, refreshToken string, err error) {

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  strconv.Itoa(userID),
		"type": "access",
		"exp":  time.Now().Add(300 * time.Second).Unix(),
	})

	accessToken, err = token.SignedString([]byte(secret))
	if err != nil {
		return "", "", err
	}

	token = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  strconv.Itoa(userID),
		"type": "refresh",
		"exp":  time.Now().Add(300 * time.Second).Unix(),
	})

	refreshToken, err = token.SignedString([]byte(secret))
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func TestAuthGuard_Private_ValidRefreshOnly_Positive_Integration(t *testing.T) {

	goodRespBody := `{
				"access_token":"fake-access-token",
				"refresh_token":"fake-refresh-token",
				"user_id":1
			}`

	fakeAuth := httptest.NewServer(
		http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {

			wr.Header().Set("Content-Type", "application/json")
			wr.WriteHeader(http.StatusOK)
			_, _ = wr.Write([]byte(goodRespBody))
		}))
	defer fakeAuth.Close()

	secret := "test_secret"
	path := "/auth/refresh"

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: fakeAuth.URL,
		},
		Auth: config.Auth{
			JWTSecret: secret,
		},
	}

	router := gin.New()

	router.Use(middleware.Recoverer(zap.NewNop()))
	router.Use(middleware.Timeout(testCfg.Timeout))
	router.Use(middleware.ValidateContentType(zap.NewNop()))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(zap.NewNop()))
	router.Use(middleware.Cors())

	// validate and refresh tokens
	router.Use(middleware.AuthGuard(testCfg, zap.NewNop()))

	router.POST(path, func(c *gin.Context) {
		c.String(http.StatusOK, goodRespBody)
	})

	wr := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid_token")

	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "valid_refresh_token"})

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusOK, wr.Code)
	assert.Contains(t, wr.Body.String(), goodRespBody)
}

func TestAuthGuard_Private_EmptyAccess_Negative_Integration(t *testing.T) {

	secret := "test_secret"
	path := "/api/auth/refresh"

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: "",
		},
		Auth: config.Auth{
			JWTSecret: secret,
		},
	}

	router := gin.New()

	router.Use(middleware.Recoverer(zap.NewNop()))
	router.Use(middleware.Timeout(testCfg.Timeout))
	router.Use(middleware.ValidateContentType(zap.NewNop()))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(zap.NewNop()))
	router.Use(middleware.Cors())

	// validate and refresh tokens
	router.Use(middleware.AuthGuard(testCfg, zap.NewNop()))

	wr := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer ")

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusUnauthorized, wr.Code)
	assert.Contains(t, wr.Body.String(), "unauthorized")
}

func TestAuthGuard_Private_NoRefresh_Negative_Integration(t *testing.T) {

	secret := "test_secret"
	path := "/api/auth/refresh"

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: "",
		},
		Auth: config.Auth{
			JWTSecret: secret,
		},
	}

	router := gin.New()

	router.Use(middleware.Recoverer(zap.NewNop()))
	router.Use(middleware.Timeout(testCfg.Timeout))
	router.Use(middleware.ValidateContentType(zap.NewNop()))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(zap.NewNop()))
	router.Use(middleware.Cors())

	// validate and refresh tokens
	router.Use(middleware.AuthGuard(testCfg, zap.NewNop()))

	wr := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid_token")

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusUnauthorized, wr.Code)
	assert.Contains(t, wr.Body.String(), "unauthorized")
}

func TestAuthGuard_Private_InvalidRefresh_Negative_Integration(t *testing.T) {

	secret := "test_secret"
	path := "/api/auth/refresh"

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: "",
		},
		Auth: config.Auth{
			JWTSecret: secret,
		},
	}

	router := gin.New()

	router.Use(middleware.Recoverer(zap.NewNop()))
	router.Use(middleware.Timeout(testCfg.Timeout))
	router.Use(middleware.ValidateContentType(zap.NewNop()))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(zap.NewNop()))
	router.Use(middleware.Cors())

	// validate and refresh tokens
	router.Use(middleware.AuthGuard(testCfg, zap.NewNop()))

	wr := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid_token")

	cookie := &http.Cookie{
		Name:  "refresh_token",
		Value: "",
	}
	req.AddCookie(cookie)

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusUnauthorized, wr.Code)
	assert.Contains(t, wr.Body.String(), "unauthorized")
}

func TestAuthGuard_Private_AuthUnavailable_Negative_Integration(t *testing.T) {

	timeout := 2 * time.Second

	fakeAuth := httptest.NewServer(http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {

		time.Sleep(timeout + 1*time.Second)
	},
	))
	defer fakeAuth.Close()

	secret := "test_secret"
	userID := 1
	path := "/api/auth/refresh"

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: fakeAuth.URL,
		},
		Auth: config.Auth{
			JWTSecret: secret,
		},
		HTTPServer: config.HTTPServer{
			Timeout: timeout,
		},
	}

	router := gin.New()

	router.Use(middleware.Recoverer(zap.NewNop()))
	router.Use(middleware.Timeout(testCfg.Timeout))
	router.Use(middleware.ValidateContentType(zap.NewNop()))
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger(zap.NewNop()))
	router.Use(middleware.Cors())

	// validate and refresh tokens
	router.Use(middleware.AuthGuard(testCfg, zap.NewNop()))

	router.POST(path, func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	wr := httptest.NewRecorder()

	_, validRefreshToken, err := generateTokens(userID, secret)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req := httptest.NewRequestWithContext(ctx, http.MethodPost, path, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid_token")

	cookie := &http.Cookie{
		Name:  "refresh_token",
		Value: validRefreshToken,
	}
	req.AddCookie(cookie)

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusGatewayTimeout, wr.Code)
	require.Contains(t, wr.Body.String(), "timeout")
}

func TestAuthGuard_Private_AuthResponse_Negative_Integration(t *testing.T) {

	secret := "test_secret"
	path := "/api/auth/refresh"

	cases := []struct {
		name           string
		authStatus     int
		authBody       string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "auth returns 400",
			authStatus:     http.StatusBadRequest,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "auth returns 401",
			authStatus:     http.StatusUnauthorized,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "auth returns 500",
			authStatus:     http.StatusInternalServerError,
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name:           "auth returns invalid json",
			authStatus:     http.StatusOK,
			authBody:       `{"user_id":1`, // error
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			fakeAuth := httptest.NewServer(
				http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {

					wr.Header().Set("Content-Type", "application/json")
					wr.WriteHeader(tc.authStatus)

					if tc.authBody != "" {
						_, _ = wr.Write([]byte(tc.authBody))
					}
				},
				))
			defer fakeAuth.Close()

			testCfg := &config.Config{
				Services: config.Services{
					AuthServiceAddr: fakeAuth.URL,
				},
				Auth: config.Auth{
					JWTSecret: secret,
				},
				HTTPServer: config.HTTPServer{
					Timeout: 5 * time.Second,
				},
			}

			router := gin.New()

			router.Use(middleware.Recoverer(zap.NewNop()))
			router.Use(middleware.Timeout(testCfg.Timeout))
			router.Use(middleware.ValidateContentType(zap.NewNop()))
			router.Use(middleware.RequestID())
			router.Use(middleware.Logger(zap.NewNop()))
			router.Use(middleware.Cors())

			// validate and refresh tokens
			router.Use(middleware.AuthGuard(testCfg, zap.NewNop()))

			router.POST(path, func(c *gin.Context) {
				c.String(http.StatusOK, "ok")
			})

			wr := httptest.NewRecorder()

			req := httptest.NewRequest(http.MethodPost, path, nil)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer invalid_access_token")

			cookie := &http.Cookie{
				Name:  "refresh_token",
				Value: "any_refresh_token",
			}
			req.AddCookie(cookie)

			router.ServeHTTP(wr, req)

			require.Equal(t, tc.expectedStatus, wr.Code)
			assert.Contains(t, wr.Body.String(), "unauthorized")
		})
	}
}
