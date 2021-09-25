package schema

import "github.com/dgrijalva/jwt-go"

// AuthorizationCheck - struct used for verification
type AuthorizationCheck struct {
	JWTUser    jwt.MapClaims
	Token      *jwt.Token
	HTTPMethod string
	Resource   string
}

// UserPermissions - struct used to hold user permission profile
type UserPermissons struct {
	Group           string
	Envs            []string
	Operations      []string
	Apis            []string
	IsSkipRoleCheck bool
}

// Response schema
type Response struct {
	Code       int    `json:"code,omitempty"`
	StatusCode string `json:"statuscode"`
	Status     string `json:"status"`
	Message    string `json:"message"`
}
