package handlers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/luigizuccarelli/iotpaas-auth-interface/pkg/connectors"
	"github.com/luigizuccarelli/iotpaas-auth-interface/pkg/schema"
	"github.com/microlib/simple"
)

var (
	readOnlyUser = schema.UserPermissons{Group: "Read Only User", Envs: []string{"PROD"}, Operations: []string{"GET"}}
	user         = schema.UserPermissons{Group: "User", Envs: []string{"PROD"}, Operations: []string{"GET", "POST"}}
	adminUser    = schema.UserPermissons{Group: "Admin User", Envs: []string{"PROD", "UAT", "DEV"}, Operations: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}}
	superUser    = schema.UserPermissons{Group: "Super User", Envs: []string{"PROD", "UAT"}, Operations: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}}
)

func TestAll(t *testing.T) {

	logger := &simple.Logger{Level: "trace"}

	t.Run("IsAlive : should pass", func(t *testing.T) {
		var STATUS int = 200
		// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
		rr := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v2/sys/info/isalive", nil)
		connectors.NewTestConnectors(logger)
		handler := http.HandlerFunc(IsAlive)
		handler.ServeHTTP(rr, req)

		body, e := ioutil.ReadAll(rr.Body)
		if e != nil {
			t.Fatalf("Should not fail : found error %v", e)
		}
		logger.Trace(fmt.Sprintf("Response %s", string(body)))
		// ignore errors here
		if rr.Code != STATUS {
			t.Errorf(fmt.Sprintf("Handler %s returned with incorrect status code - got (%d) wanted (%d)", "IsAlive", rr.Code, STATUS))
		}
	})

	t.Run("AuthHandler : should fail (no token)", func(t *testing.T) {
		var STATUS int = 403
		// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
		rr := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v1/verify", nil)
		con := connectors.NewTestConnectors(logger)
		handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			AuthHandler(w, req, con)
		})
		//req.Header.Set("Authorization", ": Bearer dsfdsfdfdsfdsfd")

		handler.ServeHTTP(rr, req)

		body, e := ioutil.ReadAll(rr.Body)
		if e != nil {
			t.Fatalf("Should not fail : found error %v", e)
		}
		logger.Trace(fmt.Sprintf("Response %s", string(body)))
		// ignore errors here
		if rr.Code != STATUS {
			t.Errorf(fmt.Sprintf("Handler %s returned with incorrect status code - got (%d) wanted (%d)", "AuthHandler", rr.Code, STATUS))
		}
	})

	t.Run("AuthHandler : should fail (forbidden)", func(t *testing.T) {
		var STATUS int = 403
		// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
		rr := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v1/verify", nil)
		con := connectors.NewTestConnectors(logger)
		handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			AuthHandler(w, req, con)
		})

		req.Header.Set("Authorization", ": Bearer dsfdsfdfdsfdsfd")

		handler.ServeHTTP(rr, req)

		body, e := ioutil.ReadAll(rr.Body)
		if e != nil {
			t.Fatalf("Should not fail : found error %v", e)
		}
		logger.Trace(fmt.Sprintf("Response %s", string(body)))
		// ignore errors here
		if rr.Code != STATUS {
			t.Errorf(fmt.Sprintf("Handler %s returned with incorrect status code - got (%d) wanted (%d)", "AuthHandler", rr.Code, STATUS))
		}
	})

	t.Run("AuthHandler : should fail (token invalid)", func(t *testing.T) {
		var STATUS int = 403
		os.Setenv("JWT_SECRETKEY", "uraidiot")

		// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
		rr := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v1/verify", nil)
		con := connectors.NewTestConnectors(logger)
		handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			AuthHandler(w, req, con)
		})

		req.Header.Add("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.oYrIXuRzmxX0DpKDbPhzDo0UtasgmWWVCvjGHYdXS74")

		handler.ServeHTTP(rr, req)

		body, e := ioutil.ReadAll(rr.Body)
		if e != nil {
			t.Fatalf("Should not fail : found error %v", e)
		}
		logger.Trace(fmt.Sprintf("Response %s", string(body)))
		// ignore errors here
		if rr.Code != STATUS {
			t.Errorf(fmt.Sprintf("Handler %s returned with incorrect status code - got (%d) wanted (%d)", "AuthHandler", rr.Code, STATUS))
		}
	})

	t.Run("AuthHandler : should pass", func(t *testing.T) {
		os.Setenv("ENV", "DEV")
		var STATUS int = 200
		os.Setenv("JWT_SECRETKEY", "uratool")

		// We create a ResponseRecorder (which satisfies http.ResponseWriter) to record the response.
		rr := httptest.NewRecorder()
		req, _ := http.NewRequest("GET", "/api/v1/verify", nil)
		con := connectors.NewTestConnectors(logger)
		req.Header.Set("X-Original-Uri", "/dbservice/api/v1/search/customers")
		handler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			AuthHandler(w, req, con)
		})

		data, err := ioutil.ReadFile("../../tests/apis.json")
		if err != nil {
			t.Fatalf("test failed trying to read apis.json")
		}

		var apisAllowed []string
		err = json.Unmarshal(data, &apisAllowed)
		if err != nil {
			t.Fatalf("test failed trying to Unmarshal apis.json")
		}

		adminUser.Apis = apisAllowed
		_, token := createJWT(adminUser, false)

		req.Header.Add("Authorization", "Bearer "+token.Raw)

		handler.ServeHTTP(rr, req)

		body, e := ioutil.ReadAll(rr.Body)
		if e != nil {
			t.Fatalf("Should not fail : found error %v", e)
		}
		logger.Trace(fmt.Sprintf("Response %s", string(body)))
		// ignore errors here
		if rr.Code != STATUS {
			t.Errorf(fmt.Sprintf("Handler %s returned with incorrect status code - got (%d) wanted (%d)", "AuthHandler", rr.Code, STATUS))
		}
	})

	testName := "isAuthorized func: should pass (url without parameters)"
	t.Run(testName, func(t *testing.T) {
		os.Setenv("ENV", "DEV")
		conn := connectors.NewTestConnectors(logger)

		data, err := ioutil.ReadFile("../../tests/apis.json")
		if err != nil {
			t.Fatalf("%s test failed trying to read apis.json", testName)
		}

		fmt.Println(string(data))

		var apisAllowed []string
		err = json.Unmarshal(data, &apisAllowed)
		if err != nil {
			t.Fatalf("%s test failed trying to Unmarshal apis.json", testName)
		}

		adminUser.Apis = apisAllowed
		jwtUser, token := createJWT(adminUser, false)

		isAccessAuthorized := isAuthorized(schema.AuthorizationCheck{JWTUser: jwtUser, Token: token, HTTPMethod: "GET", Resource: "/dbservice/api/v1/search/customers"}, conn)

		if !isAccessAuthorized {
			t.Errorf(fmt.Sprintf("%s test returned a unexpected behavior - got (%t) want (%t)", testName, isAccessAuthorized, true))
		}
	})

	testName = "isAuthorized func: should pass (url with parameters)"
	t.Run(testName, func(t *testing.T) {
		os.Setenv("ENV", "DEV")
		conn := connectors.NewTestConnectors(logger)

		data, err := ioutil.ReadFile("../../tests/apis.json")
		if err != nil {
			t.Fatalf("%s test failed trying to read apis.json", testName)
		}

		fmt.Println(string(data))

		var apisAllowed []string
		err = json.Unmarshal(data, &apisAllowed)
		if err != nil {
			t.Fatalf("%s test failed trying to Unmarshal apis.json", testName)
		}

		resources := []string{"/orderservice/api/v1/orders/customer/1234/owningorg/A1V21",
			"/auxservice/api/v1/orders/4323/owningorg/JH8j",
			"/dbservice/api/v1/customers/8762",
			"/dbservice/api/v1/search/customers",
			"/jobservice/api/v1/list/jobs/1212/6554",
			"/jobservice/api/v1/jobs/12312",
			"/auxservice/api/v1/owningorg/Uhs7sJ/sites",
			"/loginservice/api/v1/refresh/122629887",
		}

		adminUser.Apis = apisAllowed
		jwtUser, token := createJWT(adminUser, false)

		for _, resource := range resources {
			isAccessAuthorized := isAuthorized(schema.AuthorizationCheck{JWTUser: jwtUser, Token: token, HTTPMethod: "GET", Resource: resource}, conn)

			if !isAccessAuthorized {
				t.Errorf(fmt.Sprintf("%s test returned a unexpected behavior - got (%t) want (%t)", testName, isAccessAuthorized, true))
			}
		}
	})

	testName = "isAuthorized func: should pass(user roles should skip)"
	t.Run(testName, func(t *testing.T) {
		os.Setenv("ENV", "PROD")
		conn := connectors.NewTestConnectors(logger)

		data, err := ioutil.ReadFile("../../tests/apis.json")
		if err != nil {
			t.Fatalf("%s test failed trying to read apis.json", testName)
		}

		fmt.Println(string(data))

		var apisAllowed []string
		err = json.Unmarshal(data, &apisAllowed)
		if err != nil {
			t.Fatalf("%s test failed trying to Unmarshal apis.json", testName)
		}

		readOnlyUser.Apis = apisAllowed
		jwtUser, token := createJWT(readOnlyUser, true)

		isAccessAuthorized := isAuthorized(schema.AuthorizationCheck{JWTUser: jwtUser, Token: token, HTTPMethod: "GET", Resource: "/osmservice/api/v1/list/jobs"}, conn)

		if !isAccessAuthorized {
			t.Errorf(fmt.Sprintf("%s test returned a unexpected behavior - got (%t) want (%t)", testName, isAccessAuthorized, true))
		}
	})

	testName = "isAuthorized func: should fail (env is not allowed)"
	t.Run(testName, func(t *testing.T) {
		os.Setenv("ENV", "DEV")
		conn := connectors.NewTestConnectors(logger)

		data, err := ioutil.ReadFile("../../tests/apis.json")
		if err != nil {
			t.Fatalf("%s test failed trying to read apis.json", testName)
		}

		fmt.Println(string(data))

		var apisAllowed []string
		err = json.Unmarshal(data, &apisAllowed)
		if err != nil {
			t.Fatalf("%s test failed trying to Unmarshal apis.json", testName)
		}

		readOnlyUser.Apis = apisAllowed
		jwtUser, token := createJWT(readOnlyUser, false)

		isAccessAuthorized := isAuthorized(schema.AuthorizationCheck{JWTUser: jwtUser, Token: token, HTTPMethod: "GET", Resource: "/api/v1/accounts"}, conn)

		if isAccessAuthorized {
			t.Errorf(fmt.Sprintf("%s test returned a unexpected behavior - got (%t) want (%t)", testName, isAccessAuthorized, false))
		}
	})

	testName = "isAuthorized func: should fail(forbidden HTTP Method)"
	t.Run(testName, func(t *testing.T) {
		os.Setenv("ENV", "PROD")
		conn := connectors.NewTestConnectors(logger)

		data, err := ioutil.ReadFile("../../tests/apis.json")
		if err != nil {
			t.Fatalf("%s test failed trying to read apis.json", testName)
		}

		fmt.Println(string(data))

		var apisAllowed []string
		err = json.Unmarshal(data, &apisAllowed)
		if err != nil {
			t.Fatalf("%s test failed trying to Unmarshal apis.json", testName)
		}

		readOnlyUser.Apis = apisAllowed
		jwtUser, token := createJWT(readOnlyUser, false)

		isAccessAuthorized := isAuthorized(schema.AuthorizationCheck{JWTUser: jwtUser, Token: token, HTTPMethod: "POST", Resource: "/api/v1/accounts"}, conn)

		if isAccessAuthorized {
			t.Errorf(fmt.Sprintf("%s test returned a unexpected behavior - got (%t) want (%t)", testName, isAccessAuthorized, false))
		}
	})

	testName = "isAuthorized func: should fail(forbidden API access)"
	t.Run(testName, func(t *testing.T) {
		os.Setenv("ENV", "PROD")
		conn := connectors.NewTestConnectors(logger)

		data, err := ioutil.ReadFile("../../tests/apis.json")
		if err != nil {
			t.Fatalf("%s test failed trying to read apis.json", testName)
		}

		fmt.Println(string(data))

		var apisAllowed []string
		err = json.Unmarshal(data, &apisAllowed)
		if err != nil {
			t.Fatalf("%s test failed trying to Unmarshal apis.json", testName)
		}

		readOnlyUser.Apis = apisAllowed
		jwtUser, token := createJWT(readOnlyUser, false)

		isAccessAuthorized := isAuthorized(schema.AuthorizationCheck{JWTUser: jwtUser, Token: token, HTTPMethod: "GET", Resource: "api/v2/login"}, conn)

		if isAccessAuthorized {
			t.Errorf(fmt.Sprintf("%s test returned a unexpected behavior - got (%t) want (%t)", testName, isAccessAuthorized, false))
		}
	})

	testName = "claims func: should pass"
	t.Run(testName, func(t *testing.T) {
		conn := connectors.NewTestConnectors(logger)

		data, err := ioutil.ReadFile("../../tests/apis.json")
		if err != nil {
			t.Fatalf("%s test failed trying to read apis.json", testName)
		}

		fmt.Println(string(data))

		var apisAllowed []string
		err = json.Unmarshal(data, &apisAllowed)
		if err != nil {
			t.Fatalf("%s test failed trying to Unmarshal apis.json", testName)
		}

		superUser.Apis = apisAllowed

		jwtUser, _ := createJWT(superUser, false)

		userPermissions := jwtFields(jwtUser, conn)

		if userPermissions.Group != superUser.Group {
			t.Errorf(fmt.Sprintf("%s test returned unexpected data - got (%s) want (%s)", testName, userPermissions.Group, superUser.Group))
		}

		if len(userPermissions.Envs) != len(superUser.Envs) {
			t.Errorf(fmt.Sprintf("%s test returned unexpected data - got (%d) want (%d)", testName, len(userPermissions.Envs), len(superUser.Envs)))
		}

		if len(userPermissions.Apis) != len(superUser.Apis) {
			t.Errorf(fmt.Sprintf("%s test returned unexpected data - got (%d) want (%d)", testName, len(userPermissions.Apis), len(superUser.Apis)))
		}

		if len(userPermissions.Operations) != len(superUser.Operations) {
			t.Errorf(fmt.Sprintf("%s test returned unexpected data - got (%d) want (%d)", testName, len(userPermissions.Operations), len(superUser.Operations)))
		}

		if userPermissions.IsSkipRoleCheck {
			t.Errorf(fmt.Sprintf("%s test returned unexpected data - got (%t) want (%t)", testName, userPermissions.IsSkipRoleCheck, false))
		}
	})
}

func createJWT(userPermissions schema.UserPermissons, isSkipRoleCheckNeeded bool) (jwt.MapClaims, *jwt.Token) {
	secret := os.Getenv("JWT_SECRETKEY")
	var jwtKey = []byte(secret)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":              1,
		"exp":             time.Now().Add(time.Hour * time.Duration(2)).Unix(),
		"iat":             time.Now().Unix(),
		"group":           userPermissions.Group,
		"env":             userPermissions.Envs,
		"op":              userPermissions.Operations,
		"apisallowed":     userPermissions.Apis,
		"skip_role_check": isSkipRoleCheckNeeded,
	})

	tokenString, _ := token.SignedString(jwtKey)

	mapClaims := jwt.MapClaims{}

	tkn, _ := jwt.ParseWithClaims(tokenString, mapClaims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	return mapClaims, tkn
}
