<?php
session_start();
ini_set('display_errors', 'On');
error_reporting(E_ALL);
require('items.php');
require('header.php');

?>




<!DOCTYPE html>
<html>
<title>Modal Popup Box</title>
<style>
*{margin:0px; padding:0px; font-family:Helvetica, Arial, sans-serif;}

/* Full-width input fields */
input[type=text], input[type=password] {
    width: 90%;
    padding: 12px 20px;
    margin: 8px 26px;
    display: inline-block;
    border: 1px solid #ccc;
    box-sizing: border-box;
        font-size:16px;
}

/* Set a style for all buttons*/
#checkout-button {
    background-color: #4CAF50;
    color: white;
    padding: 14px 20px;
    margin: 8px 26px;
    border: none;
    cursor: pointer;
    width: 90%;
        font-size:20px;
}
#checkout-button:hover {
    opacity: 0.8;
}

/* Center the image and position the close button */
.imgcontainer {
    text-align: center;
    margin: 24px 0 12px 0;
    position: relative;
}
.avatar {
    width: 200px;
        height:200px;
    border-radius: 50%;
}

/* The Modal (background) */
.modal {
        display:none;
    position: fixed;
    z-index: 1;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    overflow: auto;
    background-color: rgba(0,0,0,0.4);
}

/* Modal Content Box */
.modal-content {
    background-color: #fefefe;
    margin: 4% auto 15% auto;
    border: 1px solid #888;
    width: 40%;
    padding-left: 15px;
    padding-right:15px;
        padding-bottom: 30px;
}

/* The Close Button (x) */
.close {
    position: absolute;
    right: 25px;
    top: 0;
    color: #000;
    font-size: 35px;
    font-weight: bold;
}
.close:hover,.close:focus {
    color: red;
    cursor: pointer;
}

/* Add Zoom Animation */
.animate {
    animation: zoom 0.6s
}
@keyframes zoom {
    from {transform: scale(0)}
    to {transform: scale(1)}
}
</style>
<body background="../background1.png">

<h1 style="text-align:center; font-size:50px; color:#fff">Modal Popup Box Login Form</h1>

<button onclick="document.getElementById('modal-wrapper').style.display='block'" id='checkout-button' style="width:200px; margin-top:200px; margin-left:160px;">
Open Popup</button>

<div id="modal-wrapper" class="modal">

  <form class="modal-content animate" action="/cart/">

    <div class="imgcontainer">
      <span onclick="document.getElementById('modal-wrapper').style.display='none'" class="close" title="Close PopUp">&times;</span>
      <img src="cart2.png" alt="Avatar" class="avatar">
      <h1 style="text-align:center">Current Cart</h1>
    </div>

    <?php showCart(); ?>

    <div class="container">
      <button type="submit" class="btn btn-success">Checkout</button>
      <button onclick="document.getElementById('modal-wrapper').style.display='none'" type="button" class="btn btn-success">Keep Shopping</button>
    </div>

  </form>

</div>

<script>
// If user clicks anywhere outside of the modal, Modal will close

var modal = document.getElementById('modal-wrapper');
window.onclick = function(event) {
    if (event.target == modal) {
        modal.style.display = "none";
    }
}
</script>

</body>
</html>



<?php 
/*
session_start();
ini_set('display_errors', 'On');
error_reporting(E_ALL);
require('items.php');
require('header.php');
 */

function showItems($category) {
	global $items;
	setlocale(LC_MONETARY, 'en_US.UTF-8');
	$filteredItems = $items[$category];
	$i = 0;
	echo '<div class="container">';
	echo '  <div class="row">';
	foreach ($filteredItems as $item) {
		if ($i != 0 && $i % 3 == 0) {
			if ($i == 0) {
			}
			else {
				echo '  </div>';
				echo '</div><br />';
				echo '<div class="container">';
				echo '  <div class="row">';
			}
		}
		if ($category != 'Commanders') {
		echo '    <div class="col-sm-4">';
		echo '      <div class="panel panel-primary">';
		echo '        <div class="panel-heading">', $item['Name'], '</div>';
		echo '        <div class="panel-body"><img src="', $item['Image_URL'] ,'" class="img-responsive" style="width:100%" alt="Image"></div>';
		echo '	      <div class="panel-footer">';
		echo '          <p>', $item['Description'], '</p>';
		echo '	        <form class="form-inline" method="post" action="/cart/">';
		echo '            <h2>', money_format('%.2n', $item['Price']), '</h2>';;
		echo '	          <input type="hidden" name="p" value="', $i ,'" />';
		echo '	          <input type="hidden" name="s" value="', $category ,'" />';
		echo '	          <input type="hidden" name="add" value="1" />';
		echo '	          <button type="submit" class="btn btn-danger">Add to Cart</button>';
		echo '	        </form>';
		echo '        </div>';
		echo '      </div>';
		echo '    </div>';
		$i++;
		}
		else{
			echo '    <div class="col-sm-4">';
                	echo '      <div class="panel panel-primary">';
                	echo '        <div class="panel-heading">', $item['Name'], '</div>';
                	echo '        <div class="panel-body"><img src="', $item['Image_URL'] ,'" class="img-responsive" style="width:100%" alt="Image"></div>';
                	echo '      </div>';
                	echo '    </div>';
               		$i++;
		}
	}
	echo '  </div>';
	echo '</div><br />';
}

function showCart() {
        setlocale(LC_MONETARY, 'en_US.UTF-8');
        global $items;
        $categories = array_keys($items);
        echo '<table class="table table-striped" width="100%">';
        echo '  <thead>';
        echo '    <tr>';
        echo '      <th>Item</th>';
        echo '      <th>Unit Price</th>';
        echo '      <th>Quantity</th>';
        echo '      <th>Subtotal</th>';
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
				echo '  <td>', $quantity, '</td>';
				/*
                                echo '  <td>';
                                echo '          <form class="form-inline" method="post" action="/cart/">';
                                echo '          <input type="text" name="q" size="2" class="form-control" value="', $quantity ,'" />';
                                echo '          <input type="hidden" name="p" value="', $i ,'" />';
                                echo '          <input type="hidden" name="s" value="', $category ,'" />';
                                echo '          <input type="hidden" name="update" value="1" />';
                                echo '          </form>';
				echo '  </td>';
				 */
				echo '  <td>', money_format('%.2n', $subtotal), '</td>';
				/*
                                echo '  <td>';
                                echo '          <form class="form-inline" method="post" action="/cart/">';
                                echo '          <input type="hidden" name="p" value="', $i ,'" />';
                                echo '          <input type="hidden" name="s" value="', $category ,'" />';
                                echo '          <input type="hidden" name="del" value="1" />';
                                echo '          </form>';
				echo '  </td>';
				 */
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
        /*
	echo '      <td>';
	echo '      </td>';
	 */
        echo '    </tr>';
        echo '  </tfoot>';
        echo '</table>';
}

?>

<?php 

$section = 'Sneakers';
if (isset($_GET['s'])) {
	$section = $_GET['s'];
}

showItems($section);

?>
<br />

<?php
	require('footer.php');
?>
