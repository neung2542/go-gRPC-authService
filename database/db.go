package database

import (
	"context"
	"fmt"
	"log"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type Database struct {
	Client   *mongo.Client
	DB       *mongo.Database
	Users    *mongo.Collection
	Tokens   *mongo.Collection
	Attempts *mongo.Collection
}

type Config struct {
	URI      string
	Database string
	Timeout  time.Duration
}

func NewDatabase(config Config) (*Database, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	// Set client options
	clientOptions := options.Client().ApplyURI(config.URI)

	// Connect to MongoDB
	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %v", err)
	}

	// Test the connection
	err = client.Ping(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to ping MongoDB: %v", err)
	}

	db := client.Database(config.Database)

	database := &Database{
		Client:   client,
		DB:       db,
		Users:    db.Collection("users"),
		Tokens:   db.Collection("invalidated_tokens"),
		Attempts: db.Collection("login_attempts"),
	}

	// Create indexes
	if err := database.createIndexes(ctx); err != nil {
		return nil, fmt.Errorf("failed to create indexes: %v", err)
	}

	log.Printf("Connected to MongoDB database: %s", config.Database)
	return database, nil
}

func (d *Database) createIndexes(ctx context.Context) error {
	// User indexes
	userIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "email", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{{Key: "is_deleted", Value: 1}},
		},
		{
			Keys: bson.D{{Key: "created_at", Value: -1}},
		},
	}

	_, err := d.Users.Indexes().CreateMany(ctx, userIndexes)
	if err != nil {
		return fmt.Errorf("failed to create user indexes: %v", err)
	}

	// Token indexes (with TTL for automatic cleanup)
	tokenIndexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "token", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0), // TTL index
		},
	}

	_, err = d.Tokens.Indexes().CreateMany(ctx, tokenIndexes)
	if err != nil {
		return fmt.Errorf("failed to create token indexes: %v", err)
	}

	// Login attempt indexes (with TTL for cleanup after 1 hour)
	attemptIndexes := []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "email", Value: 1}, {Key: "ip_address", Value: 1}},
		},
		{
			Keys:    bson.D{{Key: "timestamp", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(3600), // 1 hour TTL
		},
	}

	_, err = d.Attempts.Indexes().CreateMany(ctx, attemptIndexes)
	if err != nil {
		return fmt.Errorf("failed to create login attempt indexes: %v", err)
	}

	return nil
}

func (d *Database) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return d.Client.Disconnect(ctx)
}
