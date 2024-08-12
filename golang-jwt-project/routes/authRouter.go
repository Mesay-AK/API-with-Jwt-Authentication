package routes

import(
	"github.com/gin-gonic/gin"
	controller "golang-jwt-project/controllers"

)

func AuthRoutes(incomingRoutes *gin.Engine){
	incomingRoutes.POST("users/signup", controller.SignUp())
	incomingRoutes.POST("users/login", controller.LogIn())
}