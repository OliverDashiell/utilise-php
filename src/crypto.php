<?php 

namespace Utilise;
include 'crypto/password_store.php';

/**
* 
*/
class Crypto
{
	public static function create_password($password, $salt=null) {
		return create_password($password, $salt);
	}

	public static function validate_password($stored_password="", $guessed_password="", $update_stratagem=true, $legacy_password_validator=null) {
		return validate_password($stored_password, $guessed_password, $update_stratagem, $legacy_password_validator);
	}

	public static function change_password($stored_password, $old_password, $new_password, $new_salt=null, $legacy_password_validator=null) {
		return change_password($stored_password, $old_password, $new_password, $new_salt, $legacy_password_validator)
	}
}

?>