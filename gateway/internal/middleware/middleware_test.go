package middleware

import (
	"context"
	"fmt"
	"gateway/internal/config"
	"gateway/pkg/constants"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestMain(m *testing.M) {

	gin.SetMode(gin.ReleaseMode)
	os.Exit(m.Run())
}

func TestRecoverMiddleware_Positive(t *testing.T) {
	router := gin.New()
	router.Use(Recoverer(zap.NewNop()))

	router.GET("/ok", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	wr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ok", nil)

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusOK, wr.Code)
	assert.Equal(t, "ok", wr.Body.String())
}

func TestRecoverMiddleware_Negative(t *testing.T) {

	router := gin.New()
	router.Use(Recoverer(zap.NewNop()))

	router.GET("/panic", func(c *gin.Context) {
		panic("test panic")
	})

	wr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/panic", nil)

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusInternalServerError, wr.Code)
	assert.Contains(t, wr.Body.String(), "internal server error")
}

func TestTimeoutMiddleware_Positive(t *testing.T) {
	router := gin.New()
	router.Use(Timeout(2 * time.Second))

	var hasDeadline bool

	router.GET("/check", func(c *gin.Context) {

		_, ok := c.Request.Context().Deadline()
		hasDeadline = ok
		c.Status(http.StatusOK)
	})

	wr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/check", nil)

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusOK, wr.Code)
	assert.True(t, hasDeadline, "context should have a deadline")
}

func TestValidateContentTypeMiddleware_Positive(t *testing.T) {

	router := gin.New()
	router.Use(ValidateContentType(zap.NewNop()))

	router.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	wr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Set("Content-Type", "application/json")

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusOK, wr.Code)
	assert.Contains(t, wr.Body.String(), "ok")
}

func TestValidateContentTypeMiddleware_Negative(t *testing.T) {

	cases := []struct {
		name string
		path string
	}{
		{
			name: "login POST request returns 400",
			path: "/api/auth/login/",
		},
		{
			name: "register POST request returns 400",
			path: "/api/auth/register/",
		},
		{
			name: "refresh POST request returns 400",
			path: "/api/auth/refresh/",
		},
	}

	router := gin.New()
	router.Use(ValidateContentType(zap.NewNop()))

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			called := false

			router.POST(tc.path, func(c *gin.Context) {

				called = true // меняется, если хендлер вызывается, но в данном тесте не должен
				c.String(http.StatusOK, "ok")
			})

			wr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, tc.path, nil)

			router.ServeHTTP(wr, req)

			require.Equal(t, http.StatusBadRequest, wr.Code)
			assert.Contains(t, wr.Body.String(), "invalid request")
			assert.False(t, called)
		})
	}
}

func TestRequestIDMiddleware_Positive(t *testing.T) {

	randomRequestID := uuid.NewString()

	router := gin.New()
	router.Use(RequestID())

	router.POST("/test", func(c *gin.Context) {

		reqID, exists := c.Get(constants.RequestIDKey)
		require.True(t, exists)
		require.Equal(t, randomRequestID, reqID)

		c.String(http.StatusOK, "ok")
	})

	wr := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	req.Header.Add("X-Request-ID", randomRequestID)

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusOK, wr.Code)
	require.Equal(t, randomRequestID, wr.Header().Get("X-Request-ID"))
}

func TestRequestIDMiddleware_Negative(t *testing.T) {

	router := gin.New()
	router.Use(RequestID())

	router.POST("/test", func(c *gin.Context) {

		reqID, exists := c.Get(constants.RequestIDKey)
		require.True(t, exists)
		require.NotEmpty(t, reqID)

		_, err := uuid.Parse(reqID.(string))
		require.NoError(t, err, "X-Request-ID should be valid UUID")

		c.String(http.StatusOK, "ok")
	})

	wr := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodPost, "/test", nil)

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusOK, wr.Code)

	reqID := wr.Header().Get("X-Request-ID")
	require.NotEmpty(t, reqID)

	_, err := uuid.Parse(reqID)
	require.NoError(t, err, "X-Request-ID should be valid UUID")

}

func TestLoggerMiddleware_Positive(t *testing.T) {

	log := zap.NewNop()

	router := gin.New()
	router.Use(RequestID())
	router.Use(Logger(log))

	router.POST("/test", func(c *gin.Context) {

		enrichedLogger, exists := c.Get(constants.LoggerKey)
		require.True(t, exists)

		_, ok := enrichedLogger.(*zap.Logger)
		require.True(t, ok)

		c.String(http.StatusOK, "ok")
	})

	wr := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodPost, "/test", nil)

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusOK, wr.Code)
}

func TestCorsMiddleware_Positive(t *testing.T) {

	cases := []struct {
		name   string
		method string
	}{
		{
			name:   "request with POST",
			method: http.MethodPost,
		},
		{
			name:   "request with GET",
			method: http.MethodGet,
		},
		{
			name:   "request with PUT",
			method: http.MethodPut,
		},
		{
			name:   "request with PATCH",
			method: http.MethodPatch,
		},
		{
			name:   "request with DELETE",
			method: http.MethodDelete,
		},
	}

	router := gin.New()
	router.Use(Cors())

	router.Any("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	for _, tc := range cases {

		tc := tc
		t.Run(tc.name, func(t *testing.T) {

			wr := httptest.NewRecorder()

			req := httptest.NewRequest(tc.method, "/test", nil)
			req.Header.Set("Authorization", "Bearer token")
			req.Header.Set("Content-Type", "application/json")

			router.ServeHTTP(wr, req)

			require.Equal(t, http.StatusOK, wr.Code)

			require.Equal(t, "*", wr.Header().Get("Access-Control-Allow-Origin"))
			require.Contains(t, wr.Header().Get("Access-Control-Allow-Methods"), "POST")
			require.Contains(t, wr.Header().Get("Access-Control-Allow-Headers"), "Authorization")
		})
	}
}

func TestCorsMiddleware_Preflight(t *testing.T) {

	router := gin.New()
	router.Use(Cors())

	wr := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodOptions, "/test", nil)

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusNoContent, wr.Code)

	require.Equal(t, "*", wr.Header().Get("Access-Control-Allow-Origin"))
	require.Contains(t, wr.Header().Get("Access-Control-Allow-Methods"), "GET")
	require.Contains(t, wr.Header().Get("Access-Control-Allow-Headers"), "Authorization")
}

func TestRateLimiter_Positive(t *testing.T) {

	mtx.Lock()
	visitors = make(map[string]*rate.Limiter) // очистка глобальной мапы
	mtx.Unlock()

	router := gin.New()
	router.Use(RateLimiter())

	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	wr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "192.168.1.1:1234" // ClientIP()

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusOK, wr.Code)
	assert.Equal(t, "ok", wr.Body.String())
}

func TestRateLimiter_Negative(t *testing.T) {
	mtx.Lock()
	visitors = make(map[string]*rate.Limiter)
	mtx.Unlock()

	router := gin.New()
	router.Use(RateLimiter())

	router.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.RemoteAddr = "10.0.0.2:1234"

	limiter := GetVisitor("10.0.0.2")
	for i := 0; i < 15; i++ { // Имитируем превышение лимита
		limiter.Allow()
	}

	wr := httptest.NewRecorder()
	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusTooManyRequests, wr.Code)
	assert.Contains(t, wr.Body.String(), "too many requests")
}

func TestAuthGuard_PublicRoutes_Positive(t *testing.T) {

	testCfg := &config.Config{
		Services: config.Services{
			AuthServiceAddr: "",
		},
	}

	router := gin.New()
	router.Use(AuthGuard(testCfg, zap.NewNop()))

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
				c.String(http.StatusOK, "ok")
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

func TestAuthGuard_Private_ValidAccess_Positive(t *testing.T) {

	secret := "test_secret"
	userID := 1
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
	router.Use(AuthGuard(testCfg, zap.NewNop()))

	router.POST(path, func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	wr := httptest.NewRecorder()

	validAccessToken, _, err := GenerateTokens(userID, secret)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+validAccessToken)

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusOK, wr.Code)
	assert.Contains(t, wr.Body.String(), "ok")
}

func TestAuthGuard_Private_ValidRefreshOnly_Positive(t *testing.T) {

	fakeAuth := httptest.NewServer(http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {

		goodRespBody := `{
				"access_token":"fake-access-token",
				"refresh_token":"fake-refresh-token",
				"user_id":1
			}`

		wr.Header().Set("Content-Type", "application/json")
		wr.WriteHeader(http.StatusOK)
		_, _ = wr.Write([]byte(goodRespBody))
	},
	))
	defer fakeAuth.Close()

	secret := "test_secret"
	userID := 1
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
	router.Use(AuthGuard(testCfg, zap.NewNop()))

	router.POST(path, func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	wr := httptest.NewRecorder()

	_, validRefreshToken, err := GenerateTokens(userID, secret)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid_token")

	cookie := &http.Cookie{
		Name:  "refresh_token",
		Value: validRefreshToken,
	}
	req.AddCookie(cookie)

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusOK, wr.Code)
	assert.Contains(t, wr.Body.String(), "ok")
}

func GenerateTokens(userID int, secret string) (accessToken, refreshToken string, err error) {

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

func TestAuthGuard_Private_EmptyAccess_Negative(t *testing.T) {

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
	router.Use(AuthGuard(testCfg, zap.NewNop()))

	wr := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer ")

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusUnauthorized, wr.Code)
	assert.Contains(t, wr.Body.String(), "unauthorized")
}

func TestAuthGuard_Private_NoRefresh_Negative(t *testing.T) {

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
	router.Use(AuthGuard(testCfg, zap.NewNop()))

	wr := httptest.NewRecorder()

	req := httptest.NewRequest(http.MethodPost, path, nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer invalid_token")

	router.ServeHTTP(wr, req)

	require.Equal(t, http.StatusUnauthorized, wr.Code)
	assert.Contains(t, wr.Body.String(), "unauthorized")
}

func TestAuthGuard_Private_InvalidRefresh_Negative(t *testing.T) {

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
	router.Use(AuthGuard(testCfg, zap.NewNop()))

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

func TestAuthGuard_Private_AuthUnavailable_Negative(t *testing.T) {

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
	router.Use(AuthGuard(testCfg, zap.NewNop()))

	router.POST(path, func(c *gin.Context) {
		fmt.Println(">>> handler reached <<<")
		c.String(http.StatusOK, "ok")
	})

	wr := httptest.NewRecorder()

	_, validRefreshToken, err := GenerateTokens(userID, secret)
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

func TestAuthGuard_Private_AuthResponse_Negative(t *testing.T) {

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
			}

			router := gin.New()
			router.Use(AuthGuard(testCfg, zap.NewNop()))

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

func TestExtractAccessToken(t *testing.T) {

	cases := []struct {
		name     string
		header   string
		expected string
	}{
		{
			name:     "valid bearer token",
			header:   "Bearer valid_token",
			expected: "valid_token",
		},
		{
			name:     "missing header",
			header:   "",
			expected: "",
		},
		{
			name:     "invalid prefix",
			header:   "Token abc123",
			expected: "",
		},
		{
			name:     "extra spaces",
			header:   "Bearer valid_token extra",
			expected: "",
		},
		{
			name:     "lowercase bearer",
			header:   "bearer lowercase_token",
			expected: "lowercase_token",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {

			req, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}

			token := extractAccessToken(req)
			assert.Equal(t, tc.expected, token)
		})
	}
}

func TestValidateAccessToken(t *testing.T) {

	secret := "test_secret"

	cfg := &config.Config{
		Auth: config.Auth{
			JWTSecret: secret,
		},
	}

	// helper for token generation
	generateToken := func(secret string, claims jwt.MapClaims, method jwt.SigningMethod) string {

		token := jwt.NewWithClaims(method, claims)
		tokenString, err := token.SignedString([]byte(secret))
		require.NoError(t, err)

		return tokenString
	}

	tests := []struct {
		name        string
		token       string
		tokenType   string
		expectedErr bool
	}{
		{
			name: "valid access token",
			token: generateToken(secret, jwt.MapClaims{
				"type": "access",
				"exp":  time.Now().Add(time.Minute).Unix(),
			}, jwt.SigningMethodHS256),
			tokenType:   "access",
			expectedErr: false,
		},
		{
			name: "expired token",
			token: generateToken(secret, jwt.MapClaims{
				"type": "access",
				"exp":  time.Now().Add(-time.Minute).Unix(),
			}, jwt.SigningMethodHS256),
			tokenType:   "access",
			expectedErr: true,
		},
		{
			name: "invalid signing method",
			token: func() string {
				token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
					"type": "access",
					"exp":  time.Now().Add(time.Minute).Unix(),
				})
				return token.Raw // специально возвращаем невалидную строку
			}(),
			tokenType:   "access",
			expectedErr: true,
		},
		{
			name: "token type mismatch",
			token: generateToken(secret, jwt.MapClaims{
				"type": "refresh",
				"exp":  time.Now().Add(time.Minute).Unix(),
			}, jwt.SigningMethodHS256),
			tokenType:   "access",
			expectedErr: true,
		},
		{
			name:        "invalid token format",
			token:       "not_a_real_token",
			tokenType:   "access",
			expectedErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAccessToken(cfg, tc.token, tc.tokenType)

			if !tc.expectedErr {
				require.NoError(t, err)
			}
		})
	}
}
