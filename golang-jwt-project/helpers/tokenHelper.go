package helper

import (
	"context"
	"fmt"
	// "go/token"
	"golang-jwt-project/database"
	// "log"
	"os"
	"time"
	jwt "github.com/dgrijalva/jwt-go"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type signedDetails struct {
	Email        string
	First_name   string
	Last_name    string
	Uid          string
	User_type    string
	jwt.StandardClaims
}

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var SECRET_KEY string = os.Getenv("SECRET_KEY")

// GenerateAllTokens generates and returns access and refresh tokens.
func GenerateAllTokens(email, fName, lName, userType, uid string) (signedToken, signedRefreshToken string, err error) {
	// Create claims for access token
	claims := &signedDetails{
		Email:        email,
		First_name:   fName,
		Last_name:    lName,
		Uid:          uid,
		User_type:    userType,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * 24).Unix(), // 24 hours expiration
		},
	}

	// Create claims for refresh token
	refreshClaims := &signedDetails{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Local().Add(time.Hour * 168).Unix(), // 7 days expiration
		},
	}

	// Generate access token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) // Use HS256 if that's the intended algorithm
	signedToken, err = token.SignedString([]byte(SECRET_KEY))
	if err != nil {
		return "", "", err // Return error if token generation fails
	}

	// Generate refresh token
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims) // Use HS256 if that's the intended algorithm
	signedRefreshToken, err = refreshToken.SignedString([]byte(SECRET_KEY))
	if err != nil {
		return "", "", err // Return error if token generation fails
	}

	return signedToken, signedRefreshToken, nil
}

func ValidateToken(signedToken string) (claims *signedDetails, msg string) {
    // Parse the token and extract claims
    token, err := jwt.ParseWithClaims(
        signedToken,
        &signedDetails{},
        func(token *jwt.Token) (interface{}, error) {
            return []byte(SECRET_KEY), nil
        },
    )
    
    // Check if there was an error parsing the token
    if err != nil {
        msg = err.Error() // Set error message if token parsing fails
        return nil, msg
    }

    // Assert the token claims to our defined struct
    claims, ok := token.Claims.(*signedDetails)
    if !ok {
        msg = "Invalid token" // Set message if claims assertion fails
        return nil, msg
    }

    // Check if the token is expired
    if claims.ExpiresAt < time.Now().Local().Unix() {
        msg = "Expired Token" // Set message if token is expired
        return nil, msg
    }

    // Return claims and an empty message if everything is valid
    return claims, ""
}

func UpdateAllTokens(signedToken, signedRefreshToken, userId string) error {
    // Create a context with a timeout
    var c, cancel = context.WithTimeout(context.Background(), 100*time.Second)
    defer cancel() // Ensure the context is canceled

    // Define the update object
    var updateObj primitive.D
    updateObj = append(updateObj, bson.E{Key: "token", Value: signedToken})
    updateObj = append(updateObj, bson.E{Key: "refresh_token", Value: signedRefreshToken})

    // Update the timestamp
    updatedAt, _ := time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
    updateObj = append(updateObj, bson.E{Key: "updated_at", Value: updatedAt})

    // Define the filter and update options
    filter := bson.M{"user_id": userId}
    opt := options.Update().SetUpsert(true) // Create options with upsert set to true

    // Perform the update operation
    _, err := userCollection.UpdateOne(
        c,
        filter,
        bson.D{
            {Key: "$set", Value: updateObj},
        },
        opt,
    )
    
    if err != nil {
        return fmt.Errorf("error updating tokens: %v", err)
    }

    return nil // Return nil if the update is successful
}



