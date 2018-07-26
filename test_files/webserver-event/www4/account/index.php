<html>
<style>


.center {
    display: block;
    margin-left: auto;
    margin-right: auto;
}
.center-horizontal {
    display: flex;
    justify-content: center;
}

.center-vertical {

}

.pad-butt{
    padding-top:2em;
    padding-bottom:2em;
    padding-left:15em;
}

.gradient-background {
    background: #35cfad;
    background: linear-gradient(135deg, #2da2b7 0%, #35cfad 100%);
    border-radius: 5px;
}
.gradient-background:hover {
    filter: brightness(85%);  
}
.gradient-background:active {
    filter: brightness(70%);
}

#securely-icon {
    height:40px;
    width:auto;
    padding-right:10px;
}

.jumbotron {

    padding-left: 0;
    padding-right: 0;

}

.equalspace {
    display: flex;
    justify-content: space-between;
}

.animate {
    animation-name: grow;
    animation-duration: 5s;
    animation-iteration-count: infinite;
}
@keyframes grow {
    0%    {transform: scale(1);}
    25%   {transform: scale(1.2);}
    50%   {transform: scale(1);}
}

</style>
</html>



<?php 
session_start();
if (isset($_POST["logout"])) {
	session_unset();
	unset($_SERVER['SSA_ID']);
	$_SERVER['FIRST_LOGIN'] = 'true';
	$_SESSION['FIRST_LOGIN'] = 'true';
}
require('../items.php');
require('../header.php');
if (isset($_SESSION['name'])) {
?>
<div class="container">
<div class="jumbotron center" style="width:80%; padding-left:60px; padding-right:60px;">
  <h1 align="center">Welcome, 
    <?php 
	if ($_SESSION['firstname'] != "") {
		echo $_SESSION['firstname'], ' ', $_SESSION['lastname'];
	}
        else{
		echo $_SESSION['name'];
	}	
    ?>
  </h1>
  <hr>
  <br>

  <div class="row" style="background:transparent !important">
    <div class="col-md-12" align="center" style="background:transparent !important">
	<h2>You are logged in securely!</h2>
	<br>
        <h2></h2>
        <br>

	<div class="equalspace">

          
	  <form class="form-inline"  method="post" action="/account/">
		<div class="btn-group btn-grou-lg center-text">
			<button type="submit" class="btn btn-primary" name='logout' value="true"><font size="5">Logout</font></button>
		</div>
	  </form>
          
          <form class="form-inline" action="/">
	    <button type="submit" class="btn btn-info"><font size="5">Take Me Shopping</font></button>
          </form>
          
        </div>
<?php
}
else {
?>
<div class="container">
<div class="jumbotron center" style="width:80%; padding-left:60px; padding-right:60px;">
  <h1 align="center">Sign in</h1>
 
  <hr>
  <br>
  <div class="row" style="background:transparent !important">
    <div class="col-md-12" style="background:transparent !important">
	<h3><b>This site uses strong encryption for logging in. That means you can securely sign in with account information stored on your phone!</b></h3>
	<h3>After creating an account with Securely, no other credentials are required to sign into this site! Talk about convenient!</h3>

<?php
if (!isset($_SESSION['FIRST_LOGIN'])) {
?>
	<h3>Please click the button below to register an account with your phone:</h3>
<?php
}
else {
?>
	<h3>Please click the button below to log back into your account:</h3>
<?php
}
?>
<br>
        <br>
	<form class="form-inline" align="center" method="post" action="/login/">
		<div class="btn-group btn-grou-lg gradient-background">
			<button type="submit" class="btn" style="background:transparent !important;">

                          <img id="securely-icon" src="securely_compact_transparent_icon.png">

<?php
if (!isset($_SESSION['FIRST_LOGIN'])) {
?>
			  <font size="5" style="vertical-align: middle;">Register with Securely</font>
<?php
}
else {
?>
                          <font size="5" style="vertical-align: middle;">Login with Securely</font>
<?php
}
?>	
			</button>
		</div>
	</form>
<?php
}
?>
      </div>
    </div>
  </div>
</div><br /><br />


<div class="container">
  <div class="row">

  </div>
</div>

<?php
	require('../footer.php');
?>
