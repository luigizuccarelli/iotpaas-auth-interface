package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/luigizuccarelli/iotpaas-auth-interface/pkg/connectors"
	"github.com/luigizuccarelli/iotpaas-auth-interface/pkg/schema"
)

const (
	CONTENTTYPE     string = "Content-Type"
	APPLICATIONJSON string = "application/json"
	FORBIDDEN       string = "Forbidden"
)

// Isalive - used for liveness and readiness probes
func IsAlive(w http.ResponseWriter, r *http.Request) {
	addHeaders(w, r)
	fmt.Fprintf(w, "{ \"version\" : \""+os.Getenv("VERSION")+"\" , \"name\": \"AuthInterface\" }")
	return
}

// AuthHandler - handles all uth verfication requests
func AuthHandler(w http.ResponseWriter, r *http.Request, conn connectors.Clients) {
	var response *schema.Response

	token := r.Header.Get(strings.ToLower("Authorization"))
	conn.Trace("AuthHandler header : %s", token)

	if token == "" || !strings.Contains(token, "Bearer") || len(token) < 20 {
		w.WriteHeader(http.StatusForbidden)
		response = &schema.Response{Code: 403, StatusCode: "403", Status: "ERROR", Message: FORBIDDEN}
		b, _ := json.MarshalIndent(response, "", "	")
		fmt.Fprintf(w, string(b))
		return
	}

	// Remove Bearer
	tknStr := strings.Trim(token[7:], " ")
	conn.Info("AuthHandler token (trimmed) : %s", tknStr)
	addHeaders(w, r)

	// Initialize a new instance of `Claims`
	mapClaims := jwt.MapClaims{}
	secret := os.Getenv("JWT_SECRETKEY")
	conn.Trace("AuthAhndler JWT SECRET : %s", secret)
	urlTarget := r.Header.Get("X-Original-Uri")
	conn.Trace("URL TARGET %s", urlTarget)
	conn.Trace("REQUEST METHOD: %s", r.Method)
	conn.Trace("ENV: %s", os.Getenv("ENV"))
	conn.Trace("HEADER: %s", r.Header)
	conn.Trace("X-Real-IP: %s", r.Header.Get("X-Real-IP"))
	conn.Trace("X-Forwarded-For: %s", r.Header.Get("X-Forwarded-For"))
	conn.Trace("X-Forwarded-Proto: %s", r.Header.Get("X-Forwarded-Proto"))
	conn.Trace("X-Origin-Request-Method: %s", r.Header.Get("X-Origin-Request-Method"))

	var jwtKey = []byte(secret)
	// Parse the JWT string and store the result in `claims`.
	// Note that we are passing the key in this method as well. This method will return an error
	// if the token is invalid (if it has expired according to the expiry time we set on sign in),
	// or if the signature does not match

	tkn, err := jwt.ParseWithClaims(tknStr, mapClaims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})

	isAccessAuthorized := isAuthorized(schema.AuthorizationCheck{JWTUser: mapClaims, Token: tkn, HTTPMethod: r.Method, Resource: urlTarget}, conn)

	if err != nil || !isAccessAuthorized {
		w.WriteHeader(http.StatusForbidden)
		response = &schema.Response{Code: 403, StatusCode: "403", Status: "ERROR", Message: FORBIDDEN}
	} else {
		response = &schema.Response{Code: 200, StatusCode: "200", Status: "OK", Message: "Access granted"}
		w.WriteHeader(http.StatusOK)
	}

	b, _ := json.MarshalIndent(response, "", "	")
	conn.Debug("AuthHandler response : %s", string(b))
	fmt.Fprintf(w, string(b))
	return
}

// headers (with cors) utility
func addHeaders(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("API-KEY") != "" {
		w.Header().Set("API_KEY_PT", r.Header.Get("API_KEY"))
	}
	w.Header().Set(CONTENTTYPE, APPLICATIONJSON)
	// use this for cors
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Accept-Language", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
}

//isAuthorized returns if the user is authorized to proceed with the request
func isAuthorized(authCheck schema.AuthorizationCheck, conn connectors.Clients) bool {

	if !isTokenValid(authCheck) {
		conn.Trace("IsAuthorized func, token is invalid: %v", authCheck.Token)
		return false
	}

	return isUserAccessAuthorized(authCheck, conn)
}

func isTokenValid(authCheck schema.AuthorizationCheck) (isValid bool) {
	if authCheck.Token != nil && authCheck.Token.Valid {
		isValid = true
	}
	return
}

func isUserAccessAuthorized(authCheck schema.AuthorizationCheck, conn connectors.Clients) bool {
	permissions := jwtFields(authCheck.JWTUser, conn)

	if permissions.IsSkipRoleCheck {
		return true
	}

	if !hasEnvAccess(permissions.Envs, conn) {
		conn.Trace("IsAuthorized func, user does not have permission to use the HTTP Method: %s", authCheck.HTTPMethod)
		return false
	}

	if !hasHTTPMethodAccess(permissions.Operations, authCheck.HTTPMethod, conn) {
		conn.Trace("IsAuthorized func, user does not have permission to use the HTTP Method: %s", authCheck.HTTPMethod)
		return false
	}

	if !hasAPIAccess(permissions.Apis, authCheck.Resource, conn) {
		conn.Trace("IsAuthorized func, user does not have permission to access the endpoint: %s", authCheck.Resource)
		return false
	}

	return true
}

func hasEnvAccess(userEnvs []string, conn connectors.Clients) (isValid bool) {
	for _, v := range userEnvs {
		if v == os.Getenv("ENV") {
			isValid = true
			break
		}
	}
	return
}

func hasHTTPMethodAccess(userMethods []string, httpMethodRequested string, conn connectors.Clients) (isValid bool) {
	for _, v := range userMethods {
		if v == httpMethodRequested {
			isValid = true
			break
		}
	}
	return
}

func hasAPIAccess(userAPIsAllowed []string, apiRequested string, conn connectors.Clients) (isValid bool) {
	for _, v := range userAPIsAllowed {
		conn.Debug("DEBUG LMZ %s %s", apiRequested, v)
		if ok, _ := regexp.MatchString(v, apiRequested); ok {
			isValid = true
			break
		}
	}
	return
}

//This method returns the relevant fields of JWT necessary to check if the user access is authorized
func jwtFields(jwtUser jwt.MapClaims, conn connectors.Clients) schema.UserPermissons {

	var isSkipRoleCheck bool
	if jwtUser["skip_role_check"] != nil {
		isSkipRoleCheck = jwtUser["skip_role_check"].(bool)
		conn.Trace("claims func, JWT skip_role_check claim: %t", isSkipRoleCheck)
	}

	var group string
	if jwtUser["group"] != nil {
		group = jwtUser["group"].(string)
		conn.Trace("claims func, JWT group claim: %v", group)
	}

	var envsClaim interface{}
	var envs []string
	if jwtUser["env"] != nil {
		envsClaim = jwtUser["env"]

		for _, p := range envsClaim.([]interface{}) {
			envs = append(envs, p.(string))
		}
		conn.Trace("claims func, JWT env claim: %v", envs)
	}

	var opsClaim interface{}
	var ops []string
	if jwtUser["op"] != nil {
		opsClaim = jwtUser["op"]

		for _, p := range opsClaim.([]interface{}) {
			ops = append(ops, p.(string))
		}
		conn.Trace("claims func, JWT op claim: %v", ops)
	}

	var apisClaim interface{}
	var apis []string
	if jwtUser["apisallowed"] != nil {
		apisClaim = jwtUser["apisallowed"]

		for _, p := range apisClaim.([]interface{}) {
			apis = append(apis, p.(string))
		}
		conn.Trace("claims func, JWT apisallowed claim: %v", apis)
	}

	return schema.UserPermissons{Group: group, Envs: envs, Operations: ops, Apis: apis, IsSkipRoleCheck: isSkipRoleCheck}
}
