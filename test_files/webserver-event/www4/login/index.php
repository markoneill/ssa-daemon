<?php
session_start();
$cert_string = "No one";
if (isset($_SERVER['SSA_ID'])) {
	#$_SERVER['FIRST_LOGIN'] = 'true';
	$cert_string = $_SERVER['SSA_ID'];

	$string_arr = explode('/',$cert_string);

	$_SESSION['name'] = NULL;
	$_SESSION['location'] = NULL;
	$_SESSION['phone'] = NULL;
	$_SESSION['email'] = NULL;
	$_SESSION['firstname'] = NULL;
	$_SESSION['lastname'] = NULL;

	for ($i = 0; $i < sizeof($string_arr); $i++) {
	    $abbr = explode('=', $string_arr[$i]);
	    switch ($abbr[0]){
	        case "C":
		        $_SESSION['location'] = $abbr[1];
		        break;
	        case "CN":
		        $_SESSION['name'] = $abbr[1];
		        break;
	        case "telephoneNumber":
		        $_SESSION['phone'] = $abbr[1];
			break;
	        case "emailAddress":
		        $_SESSION['email'] = $abbr[1];
			break;
		case "GN":
			$_SESSION['firstname'] = $abbr[1];
                        break;
                case "SN":
                        $_SESSION['lastname'] = $abbr[1];
                        break;

	    }
	}
}
if (isset($_POST['checkout']) && $_POST['checkout'] == 1 && isset($_SERVER['SSA_ID'])) {
	unset($_POST['checkout']);
	header('Location: https://'.$_SERVER["SERVER_NAME"].'/new-checkout/');
}
else {
	header('Location: https://'.$_SERVER["SERVER_NAME"].'/account/');
}
echo "Redirecting";
exit();
?>
