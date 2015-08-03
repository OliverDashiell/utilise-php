<?php 

include '/crypto/password_store.php';

/**
* 
*/
class Crypto
{
	
	public static function create_password($password, $salt=null) {
		return create_password($password, $salt);
	}
}

?>