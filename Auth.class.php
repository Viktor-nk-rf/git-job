<?php
/*
Класс авторизации пользователей
*/
class Auth
{

	private static $role = 1;

	public static function logIn($login = null, $pass = null, $rememberme = false)
	{

		$isAuth = 0;

		if (!empty($login))   //Если попытка авторизации через форму, то пытаемся авторизоваться
		{
			$isAuth = self::authWithCredential($login, $pass, $rememberme);
		}
		elseif ($_SESSION['IdUserSession'])    //иначе пытаемся авторизоваться через сессии
		{
			$isAuth = self::checkAuthWithSession($_SESSION['IdUserSession']);
		}
		else // В последнем случае пытаемся авторизоваться через cookie
		{
			$isAuth = self::checkAuthWithCookie();
		}

		if (isset($_POST['ExitLogin']))
		{
			$isAuth = self::UserExit();	
			Basket::ClearBasket($isAuth);

		}

		if ($isAuth)
		{
			$IdUserSession = $_SESSION['IdUserSession'];
			

			$sql['sql'] = "select * from users where id_user = (select id_user from users_auth where hash_cookie = :hash_cookie)";
			$sql['param'] = 
				[
					'hash_cookie' => $IdUserSession,
				];
			$isAuth = db::getInstance()->Select($sql['sql'], $sql['param']);

			
			$sql['sql'] = "select users.*, roles.value from users INNER JOIN roles on users.id_role = roles.id_role where id_user = (select id_user from users_auth where hash_cookie = :hash_cookie);";
			$sql['param'] = 
				[
					'hash_cookie' => $IdUserSession,
				];
			self::$role = db::getInstance()->Select($sql['sql'], $sql['param'])[0]['value'];


		}

		return $isAuth;

	}

/*
Получаем роль текущего пользователя (уровень доступа)
*/
public static function getRole()
{
	return self::$role;
}

/*
Осуществляем удаление всех переменных, отвечающих за авторизацию пользователя.
*/
protected static function UserExit()
{
	//Удаляем запись из БД об авторизации пользователей
	$IdUserSession = $_SESSION['IdUserSession'];
	
	$sql['sql'] = "delete from users_auth where hash_cookie = :IdUserSession";
	$sql['param'] = 
		[
			'IdUserSession' => $IdUserSession,	
		];
	$user_date = db::getInstance()->Query($sql['sql'], $sql['param']);		


	//Удаляем переменные сессий
	unset($_SESSION['IdUserSession']);

	//Удаляем все переменные cookie
	setcookie('idUserCookie','', time() - 3600 * 24 * 7);

	return $isAuth = 0;
}


/*Авторизация пользователя
при использования технологии хэширования паролей
$username - имя пользователя
$password - введенный пользователем пароль
*/
protected static function authWithCredential($username, $password, $rememberme = false)
{
	$isAuth = 0;
	
	$login = $username;
	
	
	$sql['sql'] = "select id_user, login, pass from users where login = :login";
	$sql['param'] = 
		[
			'login' => $login,
		];
	$user_date = db::getInstance()->Select($sql['sql'], $sql['param']);	
	

	if ($user_date)
	{
		$passHash = $user_date[0]['pass'];
		$id_user = $user_date[0]['id_user'];
		$idUserCookie = microtime(true) . random_int(100, PHP_INT_MAX); //Используется более сложная функция генерации случайных чисел
		$idUserCookieHash = hash("sha256", $idUserCookie); //Получаем хэш 
		if (password_verify($password, $passHash))
		{
			$_SESSION['IdUserSession'] = $idUserCookieHash;
			
			$sql['sql'] = "insert into users_auth (id_user, hash_cookie, date, prim) values (:id_user, :idUserCookieHash, now(), :idUserCookie)";
			$sql['param'] = 
				[
					'id_user' => $id_user,
					'idUserCookieHash' => $idUserCookieHash,
					'idUserCookie' => $idUserCookie
					
				];
			$user_date = db::getInstance()->Query($sql['sql'], $sql['param']);				
			
			if ($rememberme == 'true')
			{
				setcookie('idUserCookie',$idUserCookieHash, time() + 3600 * 24 * 7, '/');
			}
			$isAuth = 1;
		}
		else
		{
			self::UserExit();
		}
	}
	else
	{
		self::UserExit();
	}
	
	return $isAuth;	
}

/* Авторизация при помощи сессий
При переходе между страницами происходит автоматическая авторизация
*/
protected static function checkAuthWithSession($IdUserSession)
{

	$isAuth = 0;

	$hash_cookie = $IdUserSession;

	
	$sql['sql'] = "select users.login, users_auth.* from users_auth INNER JOIN Users on users_auth.id_user = Users.id_user where users_auth.hash_cookie = :hash_cookie";
	$sql['param'] = 
		[
			'hash_cookie' => $hash_cookie,
		];
	$user_date = db::getInstance()->Select($sql['sql'], $sql['param']);			
	
	
	
	if ($user_date)
	{
		$isAuth = 1;
		$_SESSION['IdUserSession'] = $IdUserSession;
		
		if ($_COOKIE['idUserCookie'] == $IdUserSession)	
		{
			setcookie('idUserCookie','', time() - 3600 * 24 * 7, '/');
			setcookie('idUserCookie',$IdUserSession, time() + 3600 * 24 * 7, '/');
		}

	}
	else
	{
		$isAuth = 0;
		self::UserExit();
	}
	return $isAuth;
}

protected static function checkAuthWithCookie()
{
	$isAuth = 0;

	$hash_cookie = $_COOKIE['idUserCookie'];

	
	$sql['sql'] = "select * from users_auth where hash_cookie = :hash_cookie";
	$sql['param'] = 
		[
			'hash_cookie' => $hash_cookie,
		];
	$user_date = db::getInstance()->Select($sql['sql'], $sql['param']);		
	
	
	if ($user_date)
	{
		self::checkAuthWithSession($hash_cookie);
		$isAuth = 1;
	}
	else
	{
		$isAuth = 0;
		self::UserExit();
	}

	return $isAuth;
}

	public static function RegisterUser($password)
	{
		return $passHash = password_hash($password, PASSWORD_DEFAULT);
	}
	
}
?>
