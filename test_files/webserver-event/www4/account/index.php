<?php 
session_start();
require('../items.php');
require('../header.php');

$cert_string = "No one";
if (isset($_SERVER['SSA_ID'])) {
	$cert_string = $_SERVER['SSA_ID'];
}else{
    echo "you need to be logged in, n00b~!";
    exit();
}


$string_arr = explode('/',$cert_string);

$_SERVER['name'] = NULL;
$_SERVER['location'] = NULL;
$_SERVER['phone'] = NULL;
$_SERVER['email'] = NULL;

for ($i = 0; $i < sizeof($string_arr); $i++){
    $abbr = explode('=',$string_arr[$i];
    switch ($abbr[0]){
        case "C":
        $_SERVER['location'] = $abbr[1];
        break;
        case "CN":
        $_SERVER['name'] = $abbr[1];
        break;
        case "O":
        $_SERVER['phone'] = $abbr[1];
        break;
        case "emailAddress":
        $_SERVER['email'] = $abbr[1];
        break;

    }
}

?>
<div class="container">    
  <div class="row">
    <div class="col-sm-12">
      <div class="panel panel-primary">
	<?php
    if (!isset($_SERVER['name'])){
        echo "somehow, name wasn't set... ";    
    }else{
        echo 'Welcome, ', $_SERVER['name'];    
        if(isset($_POST['checkout']){
            //TODO does this work??? do I need to reset the post value or something> I don't think so
            // set button proceed to checkout
        }
    }
    ?>
      </div>
    </div>
  </div>
</div><br /><br />

<?php
	require('../footer.php');
?>
