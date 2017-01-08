package anonymize

import (
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	salt = os.Getenv("SALT") // Get the salt to be used from ENV var called SALT.
)

// Email normalizes String s to lowercase and removes all spaces and tabs.
// If e is true it also hashes s with sha512 and with a random salt from OS env-var $SALT.
// It returns an encrypted and/or normalized string.
func Email(s string, e bool) string {
	if s == "" {
		return "" // Just return an empty string if the input was empty.
	}
	s = normalizeEmail(s)
	if e {
		s = hash(s)
	}

	return s
}

// String normalizes String s to lowercase and removes all leading and trailing spaces and tabs.
// If e is true it also hashes s with sha512 and with a random salt from OS env-var $SALT.
// It returns an encrypted and/or normalized string.
func String(s string, e bool) string {
	if s == "" {
		return "" // Just return an empty string if the input was empty.
	}
	s = normalizeString(s)
	if e {
		s = hash(s)
	}

	return s
}

// Phone normalizes String s by removing all spaces and tabs and replacing the first
// "+" with "00" and removing all other characters other than 0-9.
// If e is true it also hashes s with sha512 and with a random salt from OS env-var $SALT.
// It returns an encrypted and/or normalized string.
func Phone(s string, e bool) string {
	if s == "" {
		return "" // Just return an empty string if the input was empty.
	}
	s = normalizePhone(s)
	if e {
		s = hash(s)
	}

	return s
}

// hashes the strig using SHA-512 and a "randomized"" length salt.
func hash(s string) string {
	if len(salt) < 128 {
		fmt.Println("SALT is less than 128 chars. Hashing not possible.")
		return s
	}
	saltrune, _ := utf8.DecodeRuneInString(string(s[0])) // Get the unicode number for the first character
	saltnr := saltToHigh(int(saltrune))                  // If it's over 127 (128), decrease it by just as much
	hash := sha512.Sum512([]byte(salt[0:saltnr] + s))
	hashstr := hex.EncodeToString(hash[:])
	return string(hashstr)
}

// Returns a saltnr between 1-127
func saltToHigh(saltnr int) int {
	if saltnr > 127 {
		saltnr -= 126
		saltnr = saltToHigh(saltnr)
	}
	return saltnr
}

// normalizes the e-mail
func normalizeEmail(s string) string {
	// Convert string to all lowercases and trim spaces
	s = toLower(s)
	s = removeWhitespaces(s)

	return s
}

// normalizes the string
func normalizeString(s string) string {
	// Convert string to all lowercases and trim spaces
	s = toLower(s)
	s = trimWhitespaces(s)

	return s
}

// normalizes the phone number
func normalizePhone(s string) string {
	s = leadingPlusToZeros(s)
	s = onlyNumbers(s)

	return s
}

// takes out the leading zero, but only if we didn't recieve any digits before it.
// + signs in the middle of a number is probably just there by accident and should be cleaned, not converted.
// Since we need to check for for numbers before + we can't use the bultin strings.Replace method.
func leadingPlusToZeros(s string) string {
	newstr := ""
	length := len(s)
	pos := 0
	regx := regexp.MustCompile("^([0-9]+)$")
	for i := 0; i < length; i++ {
		pos++
		// Stop looking for a + sign if we allready have gotten numbers ..
		if regx.MatchString(string(s[i])) {
			break
		}
		// If we find a + sign replace it with 00 and break the loop (we only replace once)
		if string(s[i]) == "+" {
			newstr += "00"
			break
		}
	}
	return newstr + s[pos:]
}

// Strips everything except numbers 0-9 from the string.
// If we also need to convert leading + to 00, run that before this function.
func onlyNumbers(s string) string {
	numbers := ""
	regx := regexp.MustCompile("^([0-9]+)$")
	for _, char := range s {
		if regx.MatchString(string(char)) {
			numbers += string(char)
		}
	}
	return numbers
}

// Converts the string to just lower-case.
func toLower(s string) string {
	s = strings.ToLower(s)
	return s
}

// Trims all whitespaces/tabs (leading and trailing) from the string.
func trimWhitespaces(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, " ")
	return s
}

// Removes ALL whitespaces/tabs from the string.
func removeWhitespaces(s string) string {
	s = strings.Replace(s, " ", "", -1)
	s = strings.Replace(s, "    ", "", -1)
	return s
}
