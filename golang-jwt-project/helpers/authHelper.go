package helper

import(
	"errors"
	"github.com/gin-gonic/gin"
	
)

func CheckUserType(ctx *gin.Context, role string)(err error){

	err = nil
	userType := ctx.GetString("user_type")
	if userType != role {
		err = errors.New("Unauthorized to access this resource")
		return err
	}
	return err
}

func MatchUserTypeToUid(ctx *gin.Context, userId string)(err error){
	userType := ctx.GetString("user_type")
	uid := ctx.GetString("uid")
	err = nil
	
	if userType == "USER" && uid != userId {
		err = errors.New("Unauthorized acces")
		return err
	}
	err = CheckUserType(ctx, userType)

	return err
}