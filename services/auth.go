package services

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"user-management/auth"
	"user-management/database"
	"user-management/models"
	pb "user-management/proto"
	"user-management/utils"
)

type AuthService struct {
	pb.UnimplementedAuthServiceServer
	db          *database.Database
	jwtService  *auth.JWTService
	rateLimiter *utils.RateLimiter
}

func NewAuthService(db *database.Database, jwtService *auth.JWTService) *AuthService {
	return &AuthService{
		db:          db,
		jwtService:  jwtService,
		rateLimiter: utils.NewRateLimiter(db),
	}
}

func (s *AuthService) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	// Get client IP for rate limiting
	clientIP := s.getClientIP(ctx)

	// Validate input
	if err := utils.ValidateEmail(req.Email); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	if req.Password == "" {
		return nil, status.Errorf(codes.InvalidArgument, "password is required")
	}

	// Check rate limiting
	allowed, err := s.rateLimiter.CheckRateLimit(ctx, req.Email, clientIP)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to check rate limit")
	}
	if !allowed {
		return nil, status.Errorf(codes.ResourceExhausted, "too many login attempts, please try again later")
	}

	// Find user by email
	var user models.User
	err = s.db.Users.FindOne(ctx, bson.M{
		"email":      req.Email,
		"is_deleted": false,
	}).Decode(&user)

	if err != nil {
		// Record failed attempt
		s.rateLimiter.RecordLoginAttempt(ctx, req.Email, clientIP, false)

		if err == mongo.ErrNoDocuments {
			return nil, status.Errorf(codes.NotFound, "invalid email or password")
		}
		return nil, status.Errorf(codes.Internal, "failed to find user")
	}

	// Verify password
	if !utils.CheckPasswordHash(req.Password, user.Password) {
		// Record failed attempt
		s.rateLimiter.RecordLoginAttempt(ctx, req.Email, clientIP, false)
		return nil, status.Errorf(codes.Unauthenticated, "invalid email or password")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, status.Errorf(codes.PermissionDenied, "account is deactivated/deleted")
	}

	// Generate JWT token
	token, err := s.jwtService.GenerateToken(user.ID.Hex(), user.Email)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate token")
	}

	// Record successful attempt
	s.rateLimiter.RecordLoginAttempt(ctx, req.Email, clientIP, true)

	// Convert user to protobuf
	pbUser := &pb.User{
		Id:        user.ID.Hex(),
		Email:     user.Email,
		Name:      user.Name,
		CreatedAt: timestamppb.New(user.CreatedAt),
		UpdatedAt: timestamppb.New(user.UpdatedAt),
		IsActive:  user.IsActive,
		IsDeleted: user.IsDeleted,
	}

	return &pb.LoginResponse{
		Token:   token,
		User:    pbUser,
		Message: "Login success",
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	if req.Token == "" {
		return nil, status.Errorf(codes.InvalidArgument, "token is required")
	}

	// Extract user ID from token
	userID, err := s.jwtService.ExtractUserIDFromToken(req.Token)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid token")
	}

	// Invalidate the token
	err = s.jwtService.InvalidateToken(req.Token, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to invalidate token")
	}

	return &pb.LogoutResponse{
		Message: "Logout successful",
	}, nil
}

func (s *AuthService) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// Validate input
	req.Email = utils.SanitizeString(req.Email)
	req.Name = utils.SanitizeString(req.Name)

	if err := utils.ValidateEmail(req.Email); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	if err := utils.ValidatePassword(req.Password); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	if err := utils.ValidateName(req.Name, "name"); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%s", err.Error())
	}

	// Check if user already exists
	var existingUser models.User
	err := s.db.Users.FindOne(ctx, bson.M{"email": req.Email}).Decode(&existingUser)
	if err == nil {
		return nil, status.Errorf(codes.AlreadyExists, "email already exists")
	} else if err != mongo.ErrNoDocuments {
		return nil, status.Errorf(codes.Internal, "failed to check existing user")
	}

	// Hash password
	hashedPassword, err := utils.HashPassword(req.Password)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to hash password")
	}

	// Create new user
	now := time.Now()
	user := models.User{
		Email:     req.Email,
		Password:  hashedPassword,
		Name:      req.Name,
		CreatedAt: now,
		UpdatedAt: now,
		IsActive:  true,
		IsDeleted: false,
	}

	// Insert user
	result, err := s.db.Users.InsertOne(ctx, user)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create user")
	}

	// Set the user ID from the insert result
	user.ID = result.InsertedID.(primitive.ObjectID)
	pbUser := &pb.User{
		Id:        user.ID.Hex(),
		Email:     user.Email,
		Name:      user.Name,
		CreatedAt: timestamppb.New(user.CreatedAt),
		UpdatedAt: timestamppb.New(user.UpdatedAt),
		IsActive:  user.IsActive,
		IsDeleted: user.IsDeleted,
	}
	return &pb.RegisterResponse{
		User:    pbUser,
		Message: "Registration successful",
	}, nil
}

func (s *AuthService) getClientIP(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if xRealIP := md.Get("x-real-ip"); len(xRealIP) > 0 {
			return xRealIP[0]
		}
		if xForwardedFor := md.Get("x-forwarded-for"); len(xForwardedFor) > 0 {
			return xForwardedFor[0]
		}
	}
	return "unknown"
}
