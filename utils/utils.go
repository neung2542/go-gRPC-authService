package utils

import (
	"context"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"
	"unicode"

	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"

	"user-management/database"
)

const (
	MinPasswordLength = 8
	MaxPasswordLength = 128
	MaxNameLength     = 50
	MaxEmailLength    = 128
)

// Password validation requirements
var (
	hasMinLen  = regexp.MustCompile(`.{8,}`)
	hasUpper   = regexp.MustCompile(`[A-Z]`)
	hasLower   = regexp.MustCompile(`[a-z]`)
	hasNumber  = regexp.MustCompile(`[0-9]`)
	hasSpecial = regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`)
)

type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidateEmail validates email format and length
func ValidateEmail(email string) error {
	if len(email) == 0 {
		return ValidationError{Field: "email", Message: "email is required"}
	}

	if len(email) > MaxEmailLength {
		return ValidationError{Field: "email", Message: "email is too long"}
	}

	_, err := mail.ParseAddress(email)
	if err != nil {
		return ValidationError{Field: "email", Message: "invalid email format"}
	}

	return nil
}

// ValidatePassword validates password strength
func ValidatePassword(password string) error {
	if len(password) == 0 {
		return ValidationError{Field: "password", Message: "password is required"}
	}

	if len(password) < MinPasswordLength {
		return ValidationError{Field: "password", Message: fmt.Sprintf("password must be at least %d characters", MinPasswordLength)}
	}

	if len(password) > MaxPasswordLength {
		return ValidationError{Field: "password", Message: fmt.Sprintf("password must be less than %d characters", MaxPasswordLength)}
	}

	var requirements []string

	if !hasMinLen.MatchString(password) {
		requirements = append(requirements, "at least 8 characters")
	}
	if !hasUpper.MatchString(password) {
		requirements = append(requirements, "at least one uppercase letter")
	}
	if !hasLower.MatchString(password) {
		requirements = append(requirements, "at least one lowercase letter")
	}
	if !hasNumber.MatchString(password) {
		requirements = append(requirements, "at least one number")
	}
	if !hasSpecial.MatchString(password) {
		requirements = append(requirements, "at least one special character")
	}

	if len(requirements) > 0 {
		return ValidationError{
			Field:   "password",
			Message: fmt.Sprintf("password must contain %s", strings.Join(requirements, ", ")),
		}
	}

	return nil
}

// ValidateName validates first name and last name
func ValidateName(name, fieldName string) error {
	if len(name) == 0 {
		return ValidationError{Field: fieldName, Message: fmt.Sprintf("%s is required", fieldName)}
	}

	if len(name) > MaxNameLength {
		return ValidationError{Field: fieldName, Message: fmt.Sprintf("%s is too long", fieldName)}
	}

	// Check for valid characters (letters, spaces, hyphens, apostrophes)
	for _, char := range name {
		if !unicode.IsLetter(char) && char != ' ' && char != '-' && char != '\'' {
			return ValidationError{Field: fieldName, Message: fmt.Sprintf("%s contains invalid characters", fieldName)}
		}
	}

	return nil
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

// CheckPasswordHash compares a password with its hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// RateLimiter handles login attempt rate limiting
type RateLimiter struct {
	db *database.Database
}

func NewRateLimiter(db *database.Database) *RateLimiter {
	return &RateLimiter{db: db}
}

// CheckRateLimit checks if the user has exceeded login attempts
func (r *RateLimiter) CheckRateLimit(ctx context.Context, email, ipAddress string) (bool, error) {
	// Count failed attempts in the last minute
	oneMinuteAgo := time.Now().Add(-1 * time.Minute)

	filter := bson.M{
		"email":      email,
		"ip_address": ipAddress,
		"success":    false,
		"timestamp":  bson.M{"$gte": oneMinuteAgo},
	}

	count, err := r.db.Attempts.CountDocuments(ctx, filter)
	if err != nil {
		return false, fmt.Errorf("failed to check rate limit: %v", err)
	}

	// Allow up to 5 failed attempts per minute
	return count < 5, nil
}

// RecordLoginAttempt records a login attempt
func (r *RateLimiter) RecordLoginAttempt(ctx context.Context, email, ipAddress string, success bool) error {
	attempt := bson.M{
		"email":      email,
		"ip_address": ipAddress,
		"timestamp":  time.Now(),
		"success":    success,
	}

	_, err := r.db.Attempts.InsertOne(ctx, attempt)
	if err != nil {
		return fmt.Errorf("failed to record login attempt: %v", err)
	}

	return nil
}

// SanitizeString removes leading/trailing whitespace and normalizes
func SanitizeString(s string) string {
	return strings.TrimSpace(s)
}

// BuildSearchFilter creates a MongoDB filter for name and email search
func BuildSearchFilter(nameFilter, emailFilter string) bson.M {
	filter := bson.M{"is_deleted": false}

	if nameFilter != "" {
		// Search in both first_name and last_name
		nameRegex := bson.M{"$regex": nameFilter, "$options": "i"}
		filter["$or"] = []bson.M{
			{"name": nameRegex},
		}
	}

	if emailFilter != "" {
		filter["email"] = bson.M{"$regex": emailFilter, "$options": "i"}
	}

	return filter
}
