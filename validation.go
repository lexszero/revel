package revel

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"runtime"
)

type ValidationError struct {
	Message, Key string
}

// Returns the Message.
func (e *ValidationError) String() string {
	if e == nil {
		return ""
	}
	return e.Message
}

// A Validation context manages data validation and error messages.
type Validation struct {
	Errors []*ValidationError
	keep   bool
}

func (v *Validation) Keep() {
	v.keep = true
}

func (v *Validation) Clear() {
	v.Errors = []*ValidationError{}
}

func (v *Validation) HasErrors() bool {
	return len(v.Errors) > 0
}

// Return the errors mapped by key.
// If there are multiple validation errors associated with a single key, the
// first one "wins".  (Typically the first validation will be the more basic).
func (v *Validation) ErrorMap() map[string]*ValidationError {
	m := map[string]*ValidationError{}
	for _, e := range v.Errors {
		if _, ok := m[e.Key]; !ok {
			m[e.Key] = e
		}
	}
	return m
}

// Add an error to the validation context.
func (v *Validation) Error(message string, args ...interface{}) (error *ValidationError) {
	error = (&ValidationError{}).SetMessage(message, args...)
	v.Errors = append(v.Errors, error)
	return
}

func (v *Validation) KeyError(key string, message string, args ...interface{}) (error *ValidationError) {
	error = v.Error(message, args...)
	error.Key = key
	return
}

func (e *ValidationError) SetMessage(message string, args ...interface{}) *ValidationError {
	if e != nil {
		if len(args) == 0 {
			e.Message = message
		} else {
			e.Message = fmt.Sprintf(message, args)
		}
	}
	return e
}

func (e *ValidationError) SetKey(key string) *ValidationError {
	if e != nil {
		e.Key = key
	}
	return e
}

// Test that the argument is non-nil and non-empty (if string or list)
func (v *Validation) Required(obj interface{}) *ValidationError {
	return v.apply(Required{}, obj)
}

func (v *Validation) Min(n int, min int) *ValidationError {
	return v.apply(Min{min}, n)
}

func (v *Validation) Max(n int, max int) *ValidationError {
	return v.apply(Max{max}, n)
}

func (v *Validation) Range(n, min, max int) *ValidationError {
	return v.apply(Range{Min{min}, Max{max}}, n)
}

func (v *Validation) MinSize(obj interface{}, min int) *ValidationError {
	return v.apply(MinSize{min}, obj)
}

func (v *Validation) MaxSize(obj interface{}, max int) *ValidationError {
	return v.apply(MaxSize{max}, obj)
}

func (v *Validation) Length(obj interface{}, n int) *ValidationError {
	return v.apply(Length{n}, obj)
}

func (v *Validation) Match(str string, regex *regexp.Regexp) *ValidationError {
	return v.apply(Match{regex}, str)
}

func (v *Validation) Email(str string) *ValidationError {
	return v.apply(Email{Match{emailPattern}}, str)
}

func (v *Validation) apply(chk Validator, obj interface{}) *ValidationError {
	if chk.IsSatisfied(obj) {
		return nil
	}

	// Get the default key.
	var key string
	if pc, _, line, ok := runtime.Caller(2); ok {
		f := runtime.FuncForPC(pc)
		if defaultKeys, ok := DefaultValidationKeys[f.Name()]; ok {
			key = defaultKeys[line]
		}
	} else {
		INFO.Println("Failed to get Caller information to look up Validation key")
	}

	// Add the error to the validation context.
	err := &ValidationError{
		Message: chk.DefaultMessage(),
		Key:     key,
	}
	v.Errors = append(v.Errors, err)

	// Also return it in the result.
	return err
}

// Apply a group of validators to a field, in order, and return the
// ValidationError from the first one that fails, or the last one that
// succeeds.
func (v *Validation) Check(obj interface{}, checks ...Validator) *ValidationError {
	var err *ValidationError
	for _, check := range checks {
		if err := v.apply(check, obj); err != nil {
			return err
		}
	}
	return err
}

func ValidationFilter(c *Controller, fc []Filter) {
	errors, err := restoreValidationErrors(c.Request.Request)
	c.Validation = &Validation{
		Errors: errors,
		keep:   false,
	}
	hasCookie := (err != http.ErrNoCookie)

	fc[0](c, fc[1:])

	// Add Validation errors to RenderArgs.
	c.RenderArgs["errors"] = c.Validation.ErrorMap()

	// Store the Validation errors
	var errorsValue string
	if c.Validation.keep {
		for _, error := range c.Validation.Errors {
			if error.Message != "" {
				errorsValue += "\x00" + error.Key + ":" + error.Message + "\x00"
			}
		}
	}

	// When there are errors from Validation and Keep() has been called, store the
	// values in a cookie. If there previously was a cookie but no errors, remove
	// the cookie.
	if errorsValue != "" {
		c.SetCookie(&http.Cookie{
			Name:     CookiePrefix + "_ERRORS",
			Value:    url.QueryEscape(errorsValue),
			Path:     "/",
			HttpOnly: CookieHttpOnly,
			Secure:   CookieSecure,
		})
	} else if hasCookie {
		c.SetCookie(&http.Cookie{
			Name:     CookiePrefix + "_ERRORS",
			MaxAge:   -1,
			Path:     "/",
			HttpOnly: CookieHttpOnly,
			Secure:   CookieSecure,
		})
	}
}

// Restore Validation.Errors from a request.
func restoreValidationErrors(req *http.Request) ([]*ValidationError, error) {
	var (
		err    error
		cookie *http.Cookie
		errors = make([]*ValidationError, 0, 5)
	)
	if cookie, err = req.Cookie(CookiePrefix + "_ERRORS"); err == nil {
		ParseKeyValueCookie(cookie.Value, func(key, val string) {
			errors = append(errors, &ValidationError{
				Key:     key,
				Message: val,
			})
		})
	}
	return errors, err
}

// Register default validation keys for all calls to Controller.Validation.Func().
// Map from (package).func => (line => name of first arg to Validation func)
// E.g. "myapp/controllers.helper" or "myapp/controllers.(*Application).Action"
// This is set on initialization in the generated main.go file.
var DefaultValidationKeys map[string]map[int]string
