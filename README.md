# CSRFToken

Stateless CSRF-token generation and verification.

## Properties

1. Hashes are unique per IP
2. They require a site secret, so hashes are impossible to forge.
3. Hashes expires after a certain amount of time (Default: 1 hour)

## How to use it

Initialize the library:

```php
CSRF::setSecret($strong_secret_key);
```

Add it to your forms
```html
<input type="hidden" name="_csrf" value="<?php echo CSRF::generate() ?>" />
```

And then verify the hashes are legit and still valid:

```php
if (empty($_POST['_csrf']) || !CSRF::verify($_POST['_csrf'])) {
  throw new Exception("CSRF Token is invalid");
}
```
