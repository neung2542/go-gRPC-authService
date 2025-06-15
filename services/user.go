package services

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"user-management/auth"
	"user-management/database"
	"user-management/models"
	pb "user-management/proto"
	"user-management/utils"
)

type UserService struct {
	pb.UnimplementedUserServiceServer
	db         *database.Database
	jwtService *auth.JWTService
}

func NewUserService(db *database.Database, jwtService *auth.JWTService) *UserService {
	return &UserService{
		db:         db,
		jwtService: jwtService,
	}
}

func (s *UserService) GetProfile(ctx context.Context, req *pb.GetProfileRequest) (*pb.GetProfileResponse, error) {
	// Validate user ID
	if req.UserId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user ID is required")
	}

	userObjectID, err := primitive.ObjectIDFromHex(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID format")
	}

	// Find user
	var user models.User
	err = s.db.Users.FindOne(ctx, bson.M{
		"_id":        userObjectID,
		"is_deleted": false,
	}).Decode(&user)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, status.Errorf(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "failed to retrieve user")
	}

	// Convert to protobuf
	pbUser := &pb.User{
		Id:        user.ID.Hex(),
		Email:     user.Email,
		Name:      user.Name,
		CreatedAt: timestamppb.New(user.CreatedAt),
		UpdatedAt: timestamppb.New(user.UpdatedAt),
		IsActive:  user.IsActive,
		IsDeleted: user.IsDeleted,
	}

	return &pb.GetProfileResponse{
		User: pbUser,
	}, nil
}

func (s *UserService) UpdateProfile(ctx context.Context, req *pb.UpdateProfileRequest) (*pb.UpdateProfileResponse, error) {
	// Validate user ID
	if req.UserId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user ID is required")
	}

	userObjectID, err := primitive.ObjectIDFromHex(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID format")
	}

	// Sanitize inputs
	req.Name = utils.SanitizeString(req.Name)
	req.Email = utils.SanitizeString(req.Email)

	// update
	update := bson.M{
		"$set": bson.M{
			"updated_at": time.Now(),
		},
	}

	// Validate and add fields to update
	if req.Name != "" {
		if err := utils.ValidateName(req.Name, "name"); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, err.Error())
		}
		update["$set"].(bson.M)["name"] = req.Name
	}

	if req.Email != "" {
		if err := utils.ValidateEmail(req.Email); err != nil {
			return nil, status.Errorf(codes.InvalidArgument, err.Error())
		}

		// Check if email is already taken by another user
		var existingUser models.User
		err := s.db.Users.FindOne(ctx, bson.M{
			"email": req.Email,
			"_id":   bson.M{"$ne": userObjectID},
		}).Decode(&existingUser)

		if err == nil {
			return nil, status.Errorf(codes.AlreadyExists, "email is already taken")
		} else if err != mongo.ErrNoDocuments {
			return nil, status.Errorf(codes.Internal, "failed to check email uniqueness")
		}

		update["$set"].(bson.M)["email"] = req.Email
	}

	// Update user
	result, err := s.db.Users.UpdateOne(ctx, bson.M{
		"_id":        userObjectID,
		"is_deleted": false,
	}, update)

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to update user")
	}

	if result.MatchedCount == 0 {
		return nil, status.Errorf(codes.NotFound, "user not found")
	}

	// Retrieve updated user
	var updatedUser models.User
	err = s.db.Users.FindOne(ctx, bson.M{"_id": userObjectID}).Decode(&updatedUser)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to retrieve updated user")
	}

	// Convert to protobuf
	pbUser := &pb.User{
		Id:        updatedUser.ID.Hex(),
		Email:     updatedUser.Email,
		Name:      updatedUser.Name,
		CreatedAt: timestamppb.New(updatedUser.CreatedAt),
		UpdatedAt: timestamppb.New(updatedUser.UpdatedAt),
		IsActive:  updatedUser.IsActive,
		IsDeleted: updatedUser.IsDeleted,
	}

	return &pb.UpdateProfileResponse{
		User:    pbUser,
		Message: "Profile updated successfully",
	}, nil
}

func (s *UserService) DeleteProfile(ctx context.Context, req *pb.DeleteProfileRequest) (*pb.DeleteProfileResponse, error) {
	// Validate user ID
	if req.UserId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "user ID is required")
	}

	userObjectID, err := primitive.ObjectIDFromHex(req.UserId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid user ID format")
	}

	// Soft delete the user
	result, err := s.db.Users.UpdateOne(ctx, bson.M{
		"_id":        userObjectID,
		"is_deleted": false,
	}, bson.M{
		"$set": bson.M{
			"is_deleted": true,
			"is_active":  false,
			"updated_at": time.Now(),
		},
	})

	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete user")
	}

	if result.MatchedCount == 0 {
		return nil, status.Errorf(codes.NotFound, "user not found")
	}

	return &pb.DeleteProfileResponse{
		Message: "Profile deleted successfully",
	}, nil
}

func (s *UserService) ListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	// Set default pagination values
	page := req.Page
	if page <= 0 {
		page = 1
	}
	pageSize := req.PageSize
	if pageSize <= 0 || pageSize > 100 {
		pageSize = 10
	}

	totalCount, err := s.db.Users.CountDocuments(ctx, bson.M{})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to count users")
	}

	skip := (page - 1) * pageSize

	// Find users with pagination
	findOptions := options.Find()
	findOptions.SetSkip(int64(skip))
	findOptions.SetLimit(int64(pageSize))
	findOptions.SetSort(bson.D{{Key: "created_at", Value: -1}}) // Sort by newest

	// Using empty filter bson.M{} to get all users
	cursor, err := s.db.Users.Find(ctx, bson.M{}, findOptions)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to find users")
	}
	defer cursor.Close(ctx)

	var users []models.User
	if err = cursor.All(ctx, &users); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to decode users")
	}

	// Convert to protobuf
	var pbUsers []*pb.User
	for _, user := range users {
		pbUser := &pb.User{
			Id:        user.ID.Hex(),
			Email:     user.Email,
			Name:      user.Name,
			CreatedAt: timestamppb.New(user.CreatedAt),
			UpdatedAt: timestamppb.New(user.UpdatedAt),
			IsActive:  user.IsActive,
			IsDeleted: user.IsDeleted,
		}
		pbUsers = append(pbUsers, pbUser)
	}

	return &pb.ListUsersResponse{
		Users:      pbUsers,
		TotalCount: int32(totalCount),
		Page:       page,
		PageSize:   pageSize,
	}, nil
}
