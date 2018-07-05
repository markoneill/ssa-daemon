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
	// */
}

function showCart() {
	setlocale(LC_MONETARY, 'en_US.UTF-8');
	global $items;
	$categories = array_keys($items);
	echo '<table class="table table-striped">';
	echo '  <thead>';
	echo '    <tr>';
	echo '      <th>Item</th>';
	echo '      <th>Unit Price</th>';
	echo '      <th>Quantity</th>';
	echo '      <th>Subtotal</th>';
	echo '      <th>Action</th>';
	echo '    </tr>';
	echo '  </thead>';
	echo '  <tbody>';
	$total = 0;
	foreach ($categories as $category) {
		$i = 0;
		foreach ($items[$category] as $item) {
			$quantity = 0;
			if (isset($_SESSION[$item['Name']])) {
				$quantity = $_SESSION[$item['Name']];
				$subtotal = floatval($item['Price']) * floatval($quantity);
				$total += $subtotal;
				echo '<tr>';
				echo '  <td>', $item['Name'], '</td>';
				echo '  <td>', money_format('%.2n', $item['Price']), '</td>';
				echo '  <td>';
				echo '	        <form class="form-inline" method="post" action="/cart/">';
				echo '	        <input type="text" name="q" size="2" class="form-control" value="', $quantity ,'" />';
				echo '	        <input type="hidden" name="p" value="', $i ,'" />';
				echo '	        <input type="hidden" name="s" value="', $category ,'" />';
				echo '	        <input type="hidden" name="update" value="1" />';
				echo '	        <button type="submit" class="btn btn-danger">Update</button>';
				echo '	        </form>';
				echo '  </td>';
				echo '  <td>', money_format('%.2n', $subtotal), '</td>';
				echo '  <td>';
				echo '	        <form class="form-inline" method="post" action="/cart/">';
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
	echo '      <td colspan="4" class="total">Total: ', $totalStr, '</td>';
	echo '      <td>';
	if (isset($_SERVER['SSA_ID'])) {
	    	echo '	        <form class="form-inline" method="post" action="/checkout/">';
	    	echo '	        <input type="hidden" name="checkout" value="1" />';
	    	echo '	        <button type="submit" class="btn btn-success">Checkout</button>';
	    	echo '	        </form>';
	}
        else {
	        echo '          <form class="form-inline" method="post" action="/login/">';
	        echo '          <input type="hidden" name="checkout" value="1" />';
        	echo '          <button type="submit" class="btn btn-success">Sign in to Checkout</button>';
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
	<?php showCart(); ?>
    </div>
  </div>
</div><br /><br />

<?php
	require('../footer.php');
?>
