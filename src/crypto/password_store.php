<?php

// Current password storage strategem
// Can be modified (passwords will be updated to newest spec next time correctly validated)
const ITERATIONS = 10000;
const ALGORITHM  = "sha512";
const HASH_BYTES = 64;
const SALT_BYTES = HASH_BYTES;

// Shouldn't be modified unlesss functions are modfied accordingly to handle
define("DELIMITER", ";");
define("PART_COUNT", 4);
define("HASH_ALGORITHM_INDEX", 0);
define("HASH_ITERATION_INDEX", 1);
define("HASH_SALT_INDEX", 2);
define("HASH_PBKDF2_INDEX", 3);


// Called when creating a users first password (could be put in a init of a user object)
// returns the password blob to store in password field in db or false
// password blob is formatted with the hashing algo used, itterations ran, salt used and the resulting hash value.
function create_password($password, $salt=null) {
	$crypto_strong = true;
	$salt          = ($salt === null) ? openssl_random_pseudo_bytes(SALT_BYTES, $crypto_strong) : $salt;

	if ($crypto_strong && strlen($salt) == SALT_BYTES) {
		$hash = base64_encode( hash_pbkdf2(ALGORITHM, $password, $salt, ITERATIONS, HASH_BYTES, true) );
		$salt = base64_encode( $salt );

		return ALGORITHM . DELIMITER . ITERATIONS . DELIMITER . $salt . DELIMITER . $hash;
	} 

	if ($crpyto_strong == true)      throw new Exception("System unable to generate a cryptographically secure salt for password storage. Check your server configuration meets the requirments of the openssl_random_pseudo_bytes() PHP function.");
	if (strlen($salt) == SALT_BYTES) throw new Exception("The provided salt does not meet the required salt length (in bytes) of the current strategem. Provided: ".strlen($salt).", Expected: ".SALT_BYTES);
}

// Takes the data stored in the users password field and the guessed password. optionally takes a update_strategem bool (defaults to true).
// update_strategem will check the current password storage strategem being used by the stored password and update it to the newest storage if not current strategem.
// update_strategem will only take effect if the correct password is submitted as a guess.
// Final argument is a user provided function that is called for legacy password storage validation. takes stored password and guessed password and returns true or false.
// On success of the user provided password validator function the password will be upgraded to the new storage stratagem and handed back.
// Function returns false is not correct password, true if correct or a new password blob to store aganist the user if the strategem has changed.
function validate_password($stored_password="", $guessed_password="", $update_stratagem=true, $legacy_password_validator=null) {
	// Maybe it's legacy. try and deal with that.
	if ( $legacy_password_validator != null && call_user_func($legacy_password_validator, $stored_password, $guessed_password) == true) {
		if ($update_stratagem == true) return create_password($guessed_password);
		else return true;
	}

	// Get the stored user passsord field and split around dilimiter
	$parts = explode(DELIMITER, $stored_password);

	if (count($parts) == PART_COUNT) {
		// Get the user's current password params
		$stored_algorithm  = $parts[HASH_ALGORITHM_INDEX];
		$stored_iterations = $parts[HASH_ITERATION_INDEX];
		$stored_salt       = $parts[HASH_SALT_INDEX];
		$stored_hash       = $parts[HASH_PBKDF2_INDEX];

		// decode the datablobs and get salt and hash lengths
		$decoded_salt = base64_decode( $stored_salt );
		$decoded_hash = base64_decode( $stored_hash );
		$hash_bytes   = strlen( $decoded_hash );
		$salt_bytes   = strlen( $decoded_salt );

		if ( in_array( $stored_algorithm, hash_algos() ) == false || (int)$stored_iterations == 0 ) return false; // catch any invalid parts of stored password

		// calc the guessed password's hash with the params stored with the actual password
		$hash_guess = base64_encode( hash_pbkdf2($stored_algorithm, $guessed_password, $decoded_salt, (int)$stored_iterations, $hash_bytes, true) );

		// exhaustively compare hashes to stop timing attacks
		if (_slow_equals($hash_guess, $stored_hash) === true) { 
			// password gues is correct. Check if the user is using the most up to date storage
			$outdated_statagem = ($stored_iterations != ITERATIONS || $stored_algorithm != ALGORITHM || $hash_bytes != HASH_BYTES || $salt_bytes != SALT_BYTES);

			if ($update_stratagem == true && $outdated_statagem == true) {
				return create_password($guessed_password);
			}
			return true;
		}
	}
	return false;
}

// false or password blob to put into db depending on success
function change_password($stored_password, $old_password, $new_password, $new_salt=null, $legacy_password_validator=null)
{
	// Check old password is valid. No need to update strategem as we are going to change it anyway.
	if (validate_password($stored_password, $old_password, false, $legacy_password_validator)) {
		return create_password($new_password, $new_salt);
	}

	return false;
}

function _slow_equals($a, $b)
{
    $diff = strlen($a) ^ strlen($b);
    for($i = 0; $i < strlen($a) && $i < strlen($b); $i++)
    {
        $diff |= ord($a[$i]) ^ ord($b[$i]);
    }
    return $diff === 0;
}

?>
