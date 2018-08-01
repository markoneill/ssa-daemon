
<html>
<style>

/*
td{
    font-size: 18px;
    position: relative;
    vertical-align: middle;
}

tr{
    font-size: 20px;
}
*/

input[type="number"] {
    font-size: 18px;
    
}
button[type="submit"] {
    font-size: 18px;
}
.form-inline {
     
}
.form-control-mason {
    width: 70px;
    height: 34px;
    padding-top: 6px;
    padding-right: 6px;
    padding-bottom: 6px;
    padding-left: 6px;
    color: #555;
    background-color: #fff;
    border: 1px solid #ccc;
    border-radius: 4px;
    box-shadow: inset 0 1px 1px rgba(0,0,0,.075);
}

.center-vertical {
    position: absolute;
    top: 25%;
}
.marginalbot {
    margin-bottom: 0px;
}

</style>
</html>




<?php 
session_start();
require('../items.php');
require('../header.php');

updateCart();

function updateCart() {

	//$_POST = array();
	//console.log("update");

	///*
	if (!isset($_POST['s']) || !isset($_POST['p'])) {
		return;
	}

	$section = $_POST['s'];
	$id = $_POST['p'];
	

	
	global $items;
	$item = $items[$section][$id];


	if (isset($_SESSION[$item['Name']])) {
		$quantity = $_SESSION[$item['Name']];
	}
	else {
		$quantity = 0;
	}

	$newQuantity = 0;
	



	if (isset($_POST['add'])) {
		$newQuantity = $quantity + 1;
	}
	else if (isset($_POST['del'])) {
		$newQuantity = 0;
	}
	else if (isset($_POST['update']) && isset($_POST['q'])) {
		$newQuantity = intval($_POST['q']);
	}
	

	
	if ($newQuantity > 0) {
		$_SESSION[$item['Name']] = $newQuantity;
	}
	else {
		unset($_SESSION[$item['Name']]);
	}
	return;
	//*/
}

function showTitle() {
	echo '<div class="jumbotron" align="center" style="margin-bottom:50px; padding-bottom:30px; padding-top:30px; position:relative;">';
	echo '  <img src="../cart2.png" alt="Cart" style="width:200px; height:200px; float:left;"></img>';
	echo '  <h1 style="margin-top:10px; position:absolute; top:35%; left: 40%;">Your Cart</h1>';
	echo '  <h1 style="clear:left"></h1>';
	echo '</div>';
}

function showCart() {
	setlocale(LC_MONETARY, 'en_US.UTF-8');
	global $items;
	$categories = array_keys($items);
	echo '<table class="table table-striped">';
	echo '  <thead>';
	echo '    <tr>';
	echo '      <th>Item</th>';
	echo '      <th></th>';
	echo '      <th>Unit Price</th>';
	echo '      <th>Quantity</th>';
	echo '      <th>Subtotal</th>';
	echo '      <th>Action</th>';
	echo '    </tr>';
	echo '  </thead>';
	echo '  <tbody>';
	$total = 0;
	$emptycart = true;
	foreach ($categories as $category) {
		$i = 0;
		foreach ($items[$category] as $item) {
			$quantity = 0;
			if (isset($_SESSION[$item['Name']])) {
				$emptycart = false;
				$quantity = $_SESSION[$item['Name']];
				$subtotal = floatval($item['Price']) * floatval($quantity);
				$total += $subtotal;
				echo '<tr>';
				echo '  <td align="center">';
				echo '         <img src="../', $item['Image_URL'], '" alt="Shoe" style="max-height:188px;">';
				echo '  </td>';
				echo '  <td>', $item['Name'], '</td>';
				echo '  <td>', money_format('%.2n', $item['Price']), '</td>';
				echo '  <td>';
				echo '	        <form class="form-inline marginalbot" style="min-width:160px;" method="post" action="/cart/">';
				//echo '          <div class="form-group"">';
				//echo '          <div class="col-xs-3">';
				echo '	        <input type="number" name="q" size="2" class="form-control-mason" value="', $quantity ,'" />';
				echo '	        <input type="hidden" name="p" value="', $i ,'" />';
				echo '	        <input type="hidden" name="s" value="', $category ,'" />';
				echo '	        <input type="hidden" name="update" value="1" />';
				echo '	        <button type="submit" class="btn btn-danger">Update</button>';
				//echo '          </div>';
				//echo '          </div>';
				echo '	        </form>';
				echo '  </td>';
				echo '  <td>', money_format('%.2n', $subtotal), '</td>';
				echo '  <td>';
				echo '	        <form class="form-inline marginalbot" role="form" method="post" action="/cart/">';
				echo '	        <input type="hidden" name="p" value="', $i ,'" />';
				echo '	        <input type="hidden" name="s" value="', $category ,'" />';
				echo '	        <input type="hidden" name="del" value="1" />';
				echo '	        <button type="submit" class="btn btn-danger">Remove</button>';
				echo '	        </form>';
				echo '  </td>';
				echo '</tr>';
			}
			$i++;
		}
	}
	echo '  </tbody>';
	echo '  <tfoot>';
	$totalStr = money_format('%.2n', $total);
    
	echo '    <tr>';
	echo '      <td colspan="5" class="total">Total: ', $totalStr, '</td>';
	echo '      <td>';
	if (isset($_SESSION['name'])) {
	    	echo '	        <form class="form-inline" method="post" action="/new-checkout/">';
	    	echo '	        <input type="hidden" name="checkout" value="1" />';
		echo '	        <button type="submit" class="btn btn-success"';
		if ($emptycart == true) {
			echo ' disabled';
		}
		echo '          >Checkout</button>';
	    	echo '	        </form>';
	}
        else {
	        echo '          <form class="form-inline" method="post" action="/login/">';
	        echo '          <input type="hidden" name="checkout" value="1" />';
		echo '          <button type="submit" class="btn btn-success"';
		if ($emptycart == true) {
			echo ' disabled';
		}
		echo '          >Sign in to Checkout</button>';
	        echo '          </form>';
	}
	echo '      </td>';
	echo '    </tr>';
	echo '  </tfoot>';
	echo '</table>';
}

?>
<div class="container">    
  <div class="row">
    <div class="col-sm-12">
        <?php
          showTitle();
          showCart(); 
        ?>
    </div>
  </div>
<hr>
</div><br /><br />

<?php
	require('../footer.php');
?>
