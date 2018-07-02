<?php 
session_start();
if (isset($_SERVER['SSA_ID'])) {
	require('../items.php');
	require('../header.php');
?>
<div class="container"> 
  <div class="row">
    <div class="col-md-12">
      <div class="panel">
	<h1>Welcome, <?php echo $_SESSION['name']; ?></h1>
	<p>You are logged in securely!</p>
<?php
}
else {
	require('../items.php');
	require('../header.php');
?>
<div class="container">
  <div class="row">
    <div class="col-md-12">
      <div class="panel">
	<p>This site uses strong encryption for logging in.</p>
	<p>That means you can securely sign in with keys stored on your phone!</p>
	<p>Please click the button below to register an account with your phone</p>
	<form class="form-inline" method="post" action="/login/">
	<div class="btn-group btn-grou-lg">
	  <button type="submit" class="btn btn-primary">Register</button>
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
