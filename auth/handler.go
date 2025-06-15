package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"

	"user-management/database"
	"user-management/models"
)

var (
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenBlacklisted = errors.New("token has been invalidated")
)

type JWTClaims struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	jwt.RegisteredClaims
}

type JWTService struct {
	secretKey []byte
	db        *database.Database
	tokenTTL  time.Duration
}

func NewJWTService(secretKey string, db *database.Database, tokenTTL time.Duration) *JWTService {
	return &JWTService{
		secretKey: []byte(secretKey),
		db:        db,
		tokenTTL:  tokenTTL,
	}
}

func (j *JWTService) GenerateToken(userID string, email string) (string, error) {
	claims := JWTClaims{
		UserID: userID,
		Email:  email,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.tokenTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secretKey)
}

func (j *JWTService) ValidateToken(tokenString string) (*JWTClaims, error) {
	// First check if token is blacklisted
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var invalidatedToken models.InvalidatedToken
	err := j.db.Tokens.FindOne(ctx, bson.M{"token": tokenString}).Decode(&invalidatedToken)
	if err == nil {
		return nil, ErrTokenBlacklisted
	} else if err != mongo.ErrNoDocuments {
		return nil, fmt.Errorf("error checking token blacklist: %v", err)
	}

	// Parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

func (j *JWTService) InvalidateToken(tokenString string, userID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Parse token to get expiry time
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.secretKey, nil
	})

	var expiryTime time.Time
	if err == nil {
		if claims, ok := token.Claims.(*JWTClaims); ok {
			expiryTime = claims.ExpiresAt.Time
		}
	} else {
		// If we can't parse, set expiry to current time + token TTL
		expiryTime = time.Now().Add(j.tokenTTL)
	}

	userObjectID, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return fmt.Errorf("invalid user ID: %v", err)
	}

	invalidatedToken := models.InvalidatedToken{
		Token:     tokenString,
		UserID:    userObjectID,
		ExpiresAt: expiryTime,
		CreatedAt: time.Now(),
	}

	_, err = j.db.Tokens.InsertOne(ctx, invalidatedToken)
	if err != nil {
		return fmt.Errorf("failed to invalidate token: %v", err)
	}

	return nil
}

func (j *JWTService) ExtractUserIDFromToken(tokenString string) (string, error) {
	claims, err := j.ValidateToken(tokenString)
	if err != nil {
		return "", err
	}
	return claims.UserID, nil
}
