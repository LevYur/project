package validation

import (
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"regexp"
	"sync"
)

var registerOnce sync.Once

func RegisterCustomValidators() {

	registerOnce.Do(func() {

		if v, ok := binding.Validator.Engine().(*validator.Validate); ok {
			_ = v.RegisterValidation("phone", func(fl validator.FieldLevel) bool {
				re := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
				return re.MatchString(fl.Field().String())
			})

			_ = v.RegisterValidation("birthdate", func(fl validator.FieldLevel) bool {
				re := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
				return re.MatchString(fl.Field().String())
			})

			_ = v.RegisterValidation("name", func(fl validator.FieldLevel) bool {
				re := regexp.MustCompile(`^[A-Za-zА-Яа-яЁё\s-]+$`)
				return re.MatchString(fl.Field().String())
			})
		}
	})
}
