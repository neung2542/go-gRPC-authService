package main

import (
	"log"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"user-management/auth"
	"user-management/database"

	"user-management/services"

	pb "user-management/proto"
)

type Config struct {
	Port      string
	MongoURI  string
	MongoDB   string
	JWTSecret string
	JWTExpiry time.Duration
}

func loadConfig() Config {
	return Config{
		Port:      "50051",
		MongoURI:  "mongodb://admin:password@localhost:27017", //mock URI
		MongoDB:   "user_management",
		JWTSecret: "ur-secret-key", // mock secret key
		JWTExpiry: 24 * time.Hour,
	}
}

func main() {
	// Load configuration
	config := loadConfig()

	// Initialize database
	db, err := database.NewDatabase(database.Config{
		URI:      config.MongoURI,
		Database: config.MongoDB,
		Timeout:  10 * time.Second,
	})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Initialize JWT service
	jwtService := auth.NewJWTService(config.JWTSecret, db, config.JWTExpiry)

	// Initialize services
	authService := services.NewAuthService(db, jwtService)
	userService := services.NewUserService(db, jwtService)

	server := grpc.NewServer()

	pb.RegisterAuthServiceServer(server, authService)
	pb.RegisterUserServiceServer(server, userService)

	// Enable reflection for development (remove in production)
	reflection.Register(server)

	// Create TCP listener
	listener, err := net.Listen("tcp", ":"+config.Port)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v", config.Port, err)
	}
	log.Printf("gRPC server starting on port %s", config.Port)

	if err := server.Serve(listener); err != nil {
		log.Fatalf("Failed to serve gRPC server: %v", err)
	}

}
