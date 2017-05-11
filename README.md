# anonymize

The anonymize package can anonymize and/or normalize various forms of inputs (currently text, phone numbers and e-mails).

The anonymization part will use a variable salt based on the OS ENV var $SALT and encrypt it with SHA512. The variable part is based on the first UTF8 char number of the string to be anonymized.
$SALT must be at least 128 characters long.

The normalization will make sure that the input text will always be the same independent of case or leading/trailing whitespaces and such. It will also make phone numbers have a predictable format leading with 00 and removing all non-numeric characters.

The normalize and anonmyize first normalize the data and then anonymizes it.

----------

The package has the following functions.


## Email

### EmailAnonymize

```text
EmailAnonymize anonymizes String s with sha512 and with a random salt from OS env-var $SALT.
It returns an encrypted string.
```

### EmailNormalize

```text
EmailNormalize normalizes String s to lowercase and removes all spaces and tabs.
It returns an normalized string.
```

### EmailNormAnonymize

```text
EmailNormAnonymize normalizes String s to lowercase and removes all spaces and tabs and
also hashes s with sha512 and with a random salt from OS env-var $SALT.
It returns an normalized then encrypted string.
```

## Text / String

### StringAnonymize

```text
StringAnonymize anonymizes String s with sha512 and with a random salt from OS env-var $SALT.
It returns an encrypted string.
```

### StringNormalize

```text
StringNormalize normalizes String s to lowercase and removes all leading and trailing spaces and tabs.
It returns an normalized string.
```

### StringNormAnonymize

```text
StringNormAnonymize normalizes String s to lowercase and removes all leading and trailing spaces and tabs and
hashes s with sha512 and with a random salt from OS env-var $SALT.
It returns an normalized then encrypted string.
```

## Phone Number

### PhoneAnonymize

```text
PhoneAnonymize anonymizes String s with sha512 and with a random salt from OS env-var $SALT.
It returns an encrypted string.
```

### PhoneNormalize

```text
PhoneNormalize normalizes String s by removing all spaces and tabs and replacing the first
"+" with "00" and removing all other characters other than 0-9.
It returns an normalized string.
```

### PhoneNormAnonymize

```text
PhoneNormAnonymize normalizes String s by removing all spaces and tabs and replacing the first
"+" with "00" and removing all other characters other than 0-9 and
hashes s with sha512 and with a random salt from OS env-var $SALT.
It returns an normalized then encrypted string.
```