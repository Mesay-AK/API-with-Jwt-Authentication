package main

import(
	"os"
	routes "golang-jwt-project/routes"
	"github.com/gin-gonic/gin"
	


)

func main(){
	port := os.Getenv("PORT")

	if port == ""{
		port = "8080"
	}

	router := gin.New()
	router.Use(gin.Logger())

	routes.AuthRoutes(router)
	routes.UserRoutes(router)

	router.GET("/api-1", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"success": "Acess granted for api-1"})
	} )
	router.GET("/api-2", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"success": "Acess granted for api-2"})
	} )
	router.GET("/api-3", func(ctx *gin.Context) {
		ctx.JSON(200, gin.H{"success": "Acess granted for api-3"})
	} )

	router.Run(":" + port)

}