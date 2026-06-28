package errs

import "errors"

var ErrInvalidRequest = errors.New("invalid request")
var ErrNotFound = errors.New("not found")
var ErrAlreadyExists = errors.New("already exists")
