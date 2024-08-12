package controllers

import (
	"context"
	database "golang-jwt-project/database"
	helper "golang-jwt-project/helpers"
	"golang-jwt-project/models"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strconv"
	"time"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")

var validate = validator.New()

func HashPassword(password string)string{
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPassword(userPassword, foundPassword string)(bool, string){
	err := bcrypt.CompareHashAndPassword([]byte(foundPassword), []byte(userPassword) )
	check := true
	mssg := ""

	if err != nil {
		mssg = "Invalid email or password"
		check = false
	}

	return check, mssg


}

func SignUp() gin.HandlerFunc {
    return func(ctx *gin.Context) {
        var c, cancel = context.WithTimeout(context.Background(), 100*time.Second)
        defer cancel()  // Make sure this is deferred to clean up the context

        var user models.User

        if err := ctx.BindJSON(&user); err != nil {
            ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        validationErr := validate.Struct(user)
        if validationErr != nil {
            ctx.JSON(http.StatusBadRequest, gin.H{"error": validationErr.Error()})
            return
        }

        // Check if the email already exists
        count, err := userCollection.CountDocuments(c, bson.M{"email": user.Email})
        if err != nil {
            log.Panic(err)
            ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while checking for email"})
            return
        }
        if count > 0 {
            ctx.JSON(http.StatusBadRequest, gin.H{"error": "This email already exists"})
            return
        }

        // Check if the phone number already exists
        count, err = userCollection.CountDocuments(c, bson.M{"phone": user.Phone})
        if err != nil {
            log.Panic(err)
            ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while checking for phone number"})
            return
        }
        if count > 0 {
            ctx.JSON(http.StatusBadRequest, gin.H{"error": "This phone number already exists"})
            return
        }

        // Hash the password before saving it
        password := HashPassword(*user.Password)
        user.Password = &password

        // Set the creation and update timestamps
        user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
        user.Updated_at, _ =time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

        user.User_id = new(string)
        *user.User_id = user.ID.Hex()

        // Generate tokens
        token, refreshToken, err := helper.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type, *user.User_id)
        if err != nil {
            ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate tokens"})
            return
        }
        user.Token = &token
        user.Refresh_token = &refreshToken

        // Insert the user into the database
        _, insertErr := userCollection.InsertOne(c, user)
        if insertErr != nil {
            ctx.JSON(http.StatusInternalServerError, gin.H{"error": "User item was not created"})
            return
        }

        ctx.JSON(http.StatusOK, gin.H{"message": "User created successfully"})
    }
}


func LogIn() gin.HandlerFunc {
    return func(ctx *gin.Context) {
        // Create a context with a 100-second timeout
        var c, cancel = context.WithTimeout(context.Background(), 100*time.Second)
        defer cancel() // Ensure the context is canceled

        var user models.User
        var foundUser models.User

        // Parse the JSON request body into the 'user' struct
        if err := ctx.BindJSON(&user); err != nil {
            ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
            return
        }

        // Query the database for a user with the given email
        err := userCollection.FindOne(c, bson.M{"email": user.Email}).Decode(&foundUser)
        if err != nil {
            ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid Email or Password"})
            return
        }

        // Verify the provided password against the stored password
        passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
        if !passwordIsValid {
            ctx.JSON(http.StatusUnauthorized, gin.H{"error": msg})
            return
        }

        // Generate access and refresh tokens
        token, refreshToken, err := helper.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, *foundUser.User_id)
        if err != nil {
            ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error generating tokens"})
            return
        }

        // Update tokens in the database
        err = helper.UpdateAllTokens(token, refreshToken, *foundUser.User_id)
        if err != nil {
            ctx.JSON(http.StatusInternalServerError, gin.H{"error": "Error updating tokens"})
            return
        }

        // Respond with the user details and tokens
        ctx.JSON(http.StatusOK, gin.H{
            "user":           foundUser,
            "access_token":   token,
            "refresh_token":  refreshToken,
        })
    }
}


func GetUsers() gin.HandlerFunc{
	return func(ctx *gin.Context){
		err := helper.CheckUserType(ctx, "ADMIN"); 
		if err!= nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
			}
 		var c, cancel = context.WithTimeout(context.Background(), 100*time.Second)

			recordPerPage, err := strconv.Atoi(ctx.Query("recordPerPage"))
		if err != nil || recordPerPage < 1 {
				recordPerPage = 10
			}
		page, err1 := strconv.Atoi(ctx.Query("page"))
		if err1 != nil || page < 1{
				page = 1
			}
		startIndex := (page-1) * recordPerPage
		startIndex, err = strconv.Atoi(ctx.Query("startIndex"))

		matchStage := bson.D{{Key: "$match", Value: bson.D{}},}


		groupStage := bson.D{
			{Key: "$group", Value: bson.D{
				{Key: "_id", Value: "null"},
				{Key: "total_count", Value: bson.D{{Key: "$sum", Value: 1}}},
				{Key: "data", Value: bson.D{{Key: "$push", Value: "$$ROOT"}}},
			}},
		}


		projectStage := bson.D{
			{Key: "$project", Value: bson.D{
				{Key: "_id", Value: 0},
				{Key: "total_count", Value: 1},
				{Key: "user_items", Value: bson.D{{Key: "$slice", Value: []interface{}{"$data", startIndex, recordPerPage}}}},
			}},
		}

		result, err := userCollection.Aggregate(c, mongo.Pipeline{ 
			matchStage, groupStage, projectStage,
		})

		defer cancel()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": "error occured while listing items "})
		}
		var allUsers []bson.M
		errs := result.All(ctx, &allUsers)
		if  errs!= nil{
			log.Fatal(errs)
		}
		ctx.JSON(http.StatusOK, allUsers)
	}
}

func GetUser() gin.HandlerFunc{
	return func(ctx *gin.Context){
		userId := ctx.Param("user_id")

		if err := helper.MatchUserTypeToUid(ctx, userId); err != nil {

			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()},)

			return
		}

		var c, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		var user models.User 

		err := userCollection.FindOne(c, bson.M{"user_id":userId}).Decode(&user)
		defer cancel()

		if err!= nil{
			ctx.JSON(http.StatusInternalServerError, gin.H{"error":err.Error()})
			return
		}
		ctx.JSON(http.StatusOK, user)




	}
}