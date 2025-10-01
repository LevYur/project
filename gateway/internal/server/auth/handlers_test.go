package auth

import (
	"bytes"
	"encoding/json"
	"gateway/internal/config"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type testCase struct {
	name                 string
	requestBody          []byte
	nextServiceReqURL    string
	nextServiceReqMethod string
	expectedStatus       int
	expectedBody         []byte
	expectedCT           string
}

func TestLoginHandler_Positive(t *testing.T) {

	reqBody := []byte(`{"email":"test1@example.com","password":"password1"}`)

	wr := httptest.NewRecorder()

	c, _ := gin.CreateTestContext(wr)

	// TODO: временный фейковый auth-сервер, удалить после реализации auth-сервиса
	fakeAuth := httptest.NewServer(
		http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {

			wr.WriteHeader(http.StatusOK)
			_, _ = wr.Write([]byte(`{
				"access_token":"fake-access-token",
				"refresh_token":"fake-refresh-token",
				"user_id":1
			}`))
		}))

	// TODO: временный фейковый адрес auth-сервера, поменять после реализации auth-сервиса

	req, _ := http.NewRequest(http.MethodPost, fakeAuth.URL, bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	testCfg := &config.Config{
		HTTPServer: config.HTTPServer{
			Timeout:     3 * time.Second,
			IdleTimeout: 60 * time.Second,
		},

		// TODO: временный фейковый auth-сервер, удалить после реализации auth-сервиса
		Services: config.Services{
			AuthServiceAddr: fakeAuth.URL,
		},
	}

	handler := NewHandler(testCfg, zap.NewNop())
	handler.Login(c)

	if wr.Code != http.StatusOK {
		require.Equal(t, http.StatusOK, wr.Code)
	}

	bodyBytes, err := io.ReadAll(wr.Body)
	require.NoError(t, err)

	var resp LoginResponse
	err = json.Unmarshal(bodyBytes, &resp)
	require.NoError(t, err)

	require.NotEmpty(t, resp.AccessToken)
	require.NotEmpty(t, resp.RefreshToken)
	require.NotZero(t, resp.UserID)

}

func TestRegisterHandler_Positive(t *testing.T) {

	reqBody := []byte(`{"email":"test1@example.com","password":"password1"}`)

	wr := httptest.NewRecorder()

	c, _ := gin.CreateTestContext(wr)

	// TODO: временный фейковый auth-сервер, удалить после реализации auth-сервиса
	fakeAuth := httptest.NewServer(
		http.HandlerFunc(func(wr http.ResponseWriter, req *http.Request) {

			wr.WriteHeader(http.StatusOK)
			_, _ = wr.Write([]byte(`{
				"access_token":"fake-access-token",
				"refresh_token":"fake-refresh-token",
				"user_id":1
			}`))
		}))

	// TODO: временный фейковый адрес auth-сервера, поменять после реализации auth-сервиса

	req, _ := http.NewRequest(http.MethodPost, fakeAuth.URL, bytes.NewBuffer(reqBody))
	req.Header.Set("Content-Type", "application/json")
	c.Request = req

	testCfg := &config.Config{
		HTTPServer: config.HTTPServer{
			Timeout:     3 * time.Second,
			IdleTimeout: 60 * time.Second,
		},

		// TODO: временный фейковый auth-сервер, удалить после реализации auth-сервиса
		Services: config.Services{
			AuthServiceAddr: fakeAuth.URL,
		},
	}

	handler := NewHandler(testCfg, zap.NewNop())
	handler.Login(c)

	if wr.Code != http.StatusOK {
		require.Equal(t, http.StatusOK, wr.Code)
	}

	bodyBytes, err := io.ReadAll(wr.Body)
	require.NoError(t, err)

	var resp RegisterResponse
	err = json.Unmarshal(bodyBytes, &resp)
	require.NoError(t, err)

	require.NotEmpty(t, resp.AccessToken)
	require.NotEmpty(t, resp.RefreshToken)
	require.NotZero(t, resp.UserID)
}

// TODO: func TestLoginHandler_Negative(t *testing.T) после auth

//func TestLoginHandler_Negative(t *testing.T) {
//
//	cases := []testCase{
//		{
//			name:                 "invalid JSON empty body",
//			requestBody:          []byte(`{"1"}`), // error
//			nextServiceReqURL:    "api/auth/login",
//			nextServiceReqMethod: http.MethodPost,
//			expectedStatus:       http.StatusBadRequest,
//			expectedBody:         []byte(`{"error": "invalid request"}`),
//			expectedCT:           "application/json; charset=utf-8",
//		},
//		{
//			name:                 "invalid JSON: bad email",
//			requestBody:          []byte(`{"email":"test1example.com", "password":"pass1"}`), // error
//			nextServiceReqURL:    "api/auth/login",
//			nextServiceReqMethod: http.MethodPost,
//			expectedStatus:       http.StatusBadRequest,
//			expectedBody:         []byte(`{"error":"invalid request"}`),
//			expectedCT:           "application/json; charset=utf-8",
//		},
//		{
//			name:                 "create request error: service addr empty",
//			requestBody:          nil,
//			nextServiceReqURL:    "", // error
//			nextServiceReqMethod: http.MethodPost,
//			expectedStatus:       http.StatusInternalServerError,
//			expectedBody:         []byte(`{"error":"internal server error"}`),
//			expectedCT:           "application/json; charset=utf-8",
//		},
//		{
//			name:                 "create request error: bad method",
//			requestBody:          nil,
//			nextServiceReqURL:    "api/auth/login",
//			nextServiceReqMethod: http.MethodGet, // error
//			expectedStatus:       http.StatusMethodNotAllowed,
//			expectedBody:         []byte(`{"error":"method not allowed"}`),
//			expectedCT:           "application/json; charset=utf-8",
//		},
//
//		// TODO: активировать тесты после написания auth-сервиса
//
//		//{
//		//	name:                 "send response error: auth returns 200",
//		//	requestBody:          nil,
//		//	nextServiceReqURL:    "api/auth/login",
//		//	nextServiceReqMethod: http.MethodPost,
//		//	expectedStatus:       http.StatusOK,
//		//	expectedBody:         []byte("{}"),
//		//	expectedCT:           "application/json",
//		//},
//		//{
//		//	name:                 "send response error: auth returns 400",
//		//	requestBody:          nil,
//		//	nextServiceReqURL:    "api/auth/login",
//		//	nextServiceReqMethod: http.MethodPost,
//		//	expectedStatus:       http.StatusBadRequest,
//		//	expectedBody:         []byte("{}"),
//		//	expectedCT:           "application/json",
//		//},
//		//{
//		//	name:                 "send response error: auth returns 500",
//		//	requestBody:          nil,
//		//	nextServiceReqURL:    "api/auth/login",
//		//	nextServiceReqMethod: http.MethodPost,
//		//	expectedStatus:       http.StatusInternalServerError,
//		//	expectedBody:         []byte("{}"),
//		//	expectedCT:           "application/json",
//		//},
//		//{
//		//	name:                 "send response error: auth returns body",
//		//	requestBody:          []byte(`{"msg":"body from auth"}`),
//		//	nextServiceReqURL:    "api/auth/login",
//		//	nextServiceReqMethod: http.MethodPost,
//		//	expectedBody:         []byte(`{"msg":"body from auth"}`),
//		//	expectedCT:           "application/json",
//		//},
//		//{
//		//	name:                 "send response error: auth returns header",
//		//	requestBody:          nil,
//		//	nextServiceReqURL:    "api/auth/login",
//		//	nextServiceReqMethod: http.MethodPost,
//		//	expectedStatus:       http.StatusOK,
//		//	expectedBody:         []byte("{}"),
//		//	expectedCT:           "application/json",
//		//},
//	}
//
//	for _, tt := range cases {
//
//		tt := tt
//		t.Run(tt.name, func(t *testing.T) {
//
//			// t.Parallel()
//
//			wr := httptest.NewRecorder()
//			c, _ := gin.CreateTestContext(wr)
//
//			// TODO: проблема - всегда возвращает 500,
//			// TODO: пока auth-сервис недоступен по адресу "api/auth/login"
//
//			req, _ := http.NewRequest(
//				tt.nextServiceReqMethod, tt.nextServiceReqURL, bytes.NewBuffer(tt.requestBody))
//			req.Header.Set("Content-Type", "application/json")
//
//			c.Request = req
//
//			testCfg := &config.Config{
//				HTTPServer: config.HTTPServer{
//					Timeout:     3 * time.Second,
//					IdleTimeout: 60 * time.Second,
//				},
//			}
//
//			handler := NewHandler(testCfg, zap.NewNop())
//			handler.Login(c)
//
//			assert.Equal(t, tt.expectedStatus, wr.Code)
//
//			wrBody, _ := io.ReadAll(wr.Body)
//			if tt.expectedCT == "application/json" && tt.expectedBody != nil {
//				require.JSONEq(t, string(tt.expectedBody), string(wrBody))
//			} else {
//				require.Empty(t, wrBody)
//			}
//
//			assert.Equal(t, tt.expectedCT, wr.Header().Get("Content-Type"))
//		})
//	}
//}

// TODO: func TestRegisterHandler_Negative(t *testing.T) после auth

//func TestRegisterHandler_Negative(t *testing.T) {
//	cases := []testCase{
//		{
//			name:                 "invalid JSON empty body",
//			requestBody:          []byte(""), // error
//			nextServiceReqURL:    "api/auth/register",
//			nextServiceReqMethod: http.MethodPost,
//			expectedStatus:       http.StatusBadRequest,
//			expectedBody:         []byte(`{"error": "invalid request"}`),
//			expectedCT:           "application/json",
//		},
//		{
//			name:                 "invalid JSON: bad email",
//			requestBody:          []byte(`{"email":"test1example.com", "password":"pass1"}`), // error
//			nextServiceReqURL:    "api/auth/register",
//			nextServiceReqMethod: http.MethodPost,
//			expectedStatus:       http.StatusBadRequest,
//			expectedBody:         []byte(`{"error":"invalid request"}`),
//			expectedCT:           "application/json",
//		},
//		{
//			name:                 "create request error: service addr empty",
//			requestBody:          nil,
//			nextServiceReqURL:    "", // error
//			nextServiceReqMethod: http.MethodPost,
//			expectedStatus:       http.StatusInternalServerError,
//			expectedBody:         []byte(`{"error":"internal server error"}`),
//			expectedCT:           "application/json",
//		},
//		{
//			name:                 "create request error: bad method",
//			requestBody:          nil,
//			nextServiceReqURL:    "api/auth/register",
//			nextServiceReqMethod: http.MethodGet, // error
//			expectedStatus:       http.StatusMethodNotAllowed,
//			expectedBody:         []byte(`{"error":"method not allowed"}`),
//			expectedCT:           "application/json",
//		},
//
//		// TODO: активировать тесты после написания auth-сервиса
//
//		//{
//		//	name:                 "send response error: auth returns 200",
//		//	requestBody:          nil,
//		//	nextServiceReqURL:    "api/auth/register",
//		//	nextServiceReqMethod: http.MethodPost,
//		//	expectedStatus:       http.StatusOK,
//		//	expectedBody:         []byte("{}"),
//		//	expectedCT:           "application/json",
//		//},
//		//{
//		//	name:                 "send response error: auth returns 400",
//		//	requestBody:          nil,
//		//	nextServiceReqURL:    "api/auth/register",
//		//	nextServiceReqMethod: http.MethodPost,
//		//	expectedStatus:       http.StatusBadRequest,
//		//	expectedBody:         []byte("{}"),
//		//	expectedCT:           "application/json",
//		//},
//		//{
//		//	name:                 "send response error: auth returns 500",
//		//	requestBody:          nil,
//		//	nextServiceReqURL:    "api/auth/register",
//		//	nextServiceReqMethod: http.MethodPost,
//		//	expectedStatus:       http.StatusInternalServerError,
//		//	expectedBody:         []byte("{}"),
//		//	expectedCT:           "application/json",
//		//},
//		//{
//		//	name:                 "send response error: auth returns body",
//		//	requestBody:          []byte(`{"msg":"body from auth"}`),
//		//	nextServiceReqURL:    "api/auth/register",
//		//	nextServiceReqMethod: http.MethodPost,
//		//	expectedBody:         []byte(`{"msg":"body from auth"}`),
//		//	expectedCT:           "application/json",
//		//},
//		//{
//		//	name:                 "send response error: auth returns header",
//		//	requestBody:          nil,
//		//	nextServiceReqURL:    "api/auth/register",
//		//	nextServiceReqMethod: http.MethodPost,
//		//	expectedStatus:       http.StatusOK,
//		//	expectedBody:         []byte("{}"),
//		//	expectedCT:           "application/json",
//		//},
//	}
//
//	for _, tt := range cases {
//
//		tt := tt
//		t.Run(tt.name, func(t *testing.T) {
//
//			// t.Parallel()
//
//			wr := httptest.NewRecorder()
//			c, _ := gin.CreateTestContext(wr)
//
//			// TODO: проблема - всегда возвращает 500,
//			// TODO: пока auth-сервис недоступен по адресу "api/auth/register"
//			req, _ := http.NewRequest(
//				tt.nextServiceReqMethod, tt.nextServiceReqURL, bytes.NewBuffer(tt.requestBody))
//			req.Header.Set("Content-Type", "application/json")
//
//			c.Request = req
//
//			testCfg := &config.Config{
//				HTTPServer: config.HTTPServer{
//					Timeout:     3 * time.Second,
//					IdleTimeout: 60 * time.Second,
//				},
//			}
//
//			handler := NewHandler(testCfg, zap.NewNop())
//			handler.Register(c)
//
//			assert.Equal(t, tt.expectedStatus, wr.Code)
//
//			wrBody, _ := io.ReadAll(wr.Body)
//			if tt.expectedCT == "application/json" && tt.expectedBody != nil {
//				require.JSONEq(t, string(tt.expectedBody), string(wrBody))
//			} else {
//				require.Empty(t, wrBody)
//			}
//
//			assert.Equal(t, tt.expectedCT, wr.Header().Get("Content-Type"))
//		})
//	}
//}
