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

.pad-butt{
    padding-top:2em;
    padding-bottom:2em;
    padding-left:15em;
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
}
require('../items.php');
require('../header.php');
if (isset($_SESSION['name'])) {
?>
<div class="container"> 
  <div class="row">
    <div class="col-md-12">
      <div class="panel">
	<h1>Welcome, <?php echo $_SESSION['name']; ?></h1>
	<h2>You are logged in securely!</h2>
	<form class="form-inline pad-butt" method="post" action="/account/">
		<div class="btn-group btn-grou-lg center-text">
			<button type="submit" class="btn btn-primary" name='logout' value="true"><font size="5">Logout</font></button>
		</div>
	</form>
<?php
}
else {
?>
<div class="container">
  <div class="row">
    <div class="col-md-12">
      <div class="panel">
	<h2>This site uses strong encryption for logging in.<br>That means you can securely sign in with keys stored on your phone!</h2>
	<h3>Please click the button below to register an account with your phone</h3>
	<form class="form-inline pad-butt" method="post" action="/login/">
		<div class="btn-group btn-grou-lg">
			<button type="submit" class="btn btn-primary"><font size="5">Register</font></button>
		</div>
        </form>
<?php
}
?>
      </div>
    </div>
  </div>
</div><br /><br />
<?php
	require('../footer.php');
?>
