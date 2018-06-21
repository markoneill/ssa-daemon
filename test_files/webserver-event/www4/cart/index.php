<?php 
session_start();
require('../header.php');

$name = "No one";
if (isset($_SERVER['SSA_ID'])) {
	$name = $_SERVER['SSA_ID'];
}

?>
<div class="container">    
  <div class="row">
    <div class="col-sm-12">
      <div class="panel panel-primary">
	<?php echo 'Welcome, ', $name; ?>
      </div>
    </div>
  </div>
</div><br /><br />

<?php
	require('../footer.php');
?>
