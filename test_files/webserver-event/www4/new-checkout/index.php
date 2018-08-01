<html>
<style>


.center {
    display: block;
    margin-left: auto;
    margin-right: auto;
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

.circle-incomplete {
    width: 50px;
    height: 50px;
    border-radius: 50%;
    font-size: 30px;
    color: #fff;
    line-height: 50px;
    text-align: center;
    background: #555;
}
.circle-current {
    width: 50px;
    height: 50px;
    border-radius: 50%;
    font-size: 30px;
    color: #fff;
    line-height: 50px;
    text-align: center;
    background: #e18b42;
}
.circle-complete {
    width: 50px;
    height: 50px;
    border-radius: 50%;
    font-size: 30px;
    color: #fff;
    line-height: 50px;
    text-align: center;
    background: #1bdc71;
}


.text-incomplete {
    font-size:20px;
}
.text-current {
    font-size:20px;
    color: #e18b42;
}
.text-complete {
    font-size:20px;
    color: #1bdc71;
}

.color-current {
    color: #e18b42;
}
.color-complete {
    color: #1bdc71;
}

#securely-icon {
    height:40px;
    width:auto;
    padding-right:10px;
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
require('../items.php');
require('../header.php');


function checkout() {
//unset($_POST['checkout']);
if (isset($_POST['purchase'])) {
	//print_r($_POST);
	if ($_POST['purchase'] == "success") {
		//print($_POST['purchase']);
		echo '<div class="container">';
		echo '	<div class="row">';
		echo '		<div class="col-md-12">';
		echo '            <div class="jumbotron">';
		echo '                           <img class="center animate" src="check5.png" alt="Purchase Complete" width="150" height="150"></img>';
		echo '				 <h1 class="text-center"><font size="7" color="#1bdc71"><b>Thank You! Your order has been placed</b></font></h1>';
		echo '				 <h2 class="text-center">Come back anytime to PayMore!</h2>';
		echo '                           <br>';
		echo '                           <br>';
		echo '                           <div align="center">';
		echo '                             <div class="btn-group gradient-background">';
		echo '                               <button class="btn gradient-background"';
		echo '                                 onclick="window.open(\'https://byu.az1.qualtrics.com/jfe/form/SV_9ZT7LS9FzvRCGeF\')">';
		//echo '                                 <a href="https://byu.az1.qualtrics.com/jfe/form/SV_9ZT7LS9FzvRCGeF"></a>';
		echo '                                 <img id="securely-icon" src="../account/securely_compact_transparent_icon.png">';
		echo '                                 <font size="5" style="vertical-align: middle;">Tell us about your experience!</font>';
		echo '                               </button>';
		echo '                             </div>';
		echo '                           </div>';
		echo '            </div>';
		echo '		</div>';
		echo '	</div>';
		echo '</div>';
		
		global $items;
		$categories = array_keys($items);
		foreach ($categories as $category) {
			$i = 0;
			foreach ($items[$category] as $item) {
				$quantity = 0;
				if (isset($_SESSION[$item['Name']])) {
					unset($_SESSION[$item['Name']]);
				}
			}
		}
		# session_destroy();
		exit();
	} else {
		echo '<div class="container alert alert-danger">';
		echo '	<div class="row">';
		echo '		<div class="col-md-8 col-md-offset-2">';
		echo '				 <h1 class="text-center">Checkout Failed!</h1>';
		echo '				 <p class="text-center">Your secure credit card was rejected</p>';
		echo '		</div>';
		echo '	</div>';
		echo '</div>';
		$_POST['confirm'] = 'y';
	}
}
return;
}

function showCart() {
	setlocale(LC_MONETARY, 'en_US.UTF-8');
	global $items;
	$categories = array_keys($items);

	echo '<div class="container">';

        echo '<div class="row">';
        echo '    <div class="col-md-3" style="width:29.16666667%;"></div> <!-- col-md-3.5 -->';
        echo '    <div class="col-md-1" align="center" style="padding-right:0px; padding-left:0px; padding-top:45px;">';
        echo '        <div class="circle-complete" style="margin-left:0px; margin-right:0px;">1</div>';
        echo '        <div class="text-complete">Shipping</div>';
        echo '    </div>';
        echo '    <div class="col-md-1" style="padding-right:0px; padding-left:0px;">';
        echo '        <div class="color-complete"style="font-size:90px; text-align:center;">---</div>';
        echo '    </div>';
        echo '    <div class="col-md-1" align="center" style="padding-right:0px; padding-left:0px; padding-top:45px;">';
        echo '        <div class="circle-current">2</div>';
        echo '        <div class="text-current">Billing</div>';
        echo '    </div>';
        echo '    <div class="col-md-1" style="padding-right:0px; padding-left:0px;">';
        echo '        <div style="font-size:90px; text-align:center;">---</div>';
        echo '    </div>';
        echo '    <div class="col-md-1" align="center" style="padding-right:0px; padding-left:0px; padding-top:45px;">';
        echo '        <div class="circle-incomplete">3</div>';
        echo '        <div class="text-incomplete">Order Complete!</div>';
        echo '    </div>';
        echo '    <div class="col-md-3" style="width:29.16666667%;"></div> <!-- col-md-3.5 -->';
	echo '</div>';
	echo '<br/>';


	echo '  <div class="row">';
	echo '    <div class="col-sm-9">';

	echo '<table class="table table-striped">';
	echo '  <thead>';
	echo '    <tr>';
	echo '      <th>Item</th>';
	echo '      <th></th>';
	echo '      <th>Unit Price</th>';
	echo '      <th>Quantity</th>';
	echo '      <th>Subtotal</th>';
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
				echo '<tr class="active">';
				echo '  <td align="center">';
				#echo '    <div class="container">';
				#echo '      <div class="row">';
				#echo '        <div class="col-sm-4">';
				#echo '          <div class="panel panel-primary">';
				#echo '            <div class="panel-body"><img src="../', $item['Image_URL'], '" alt="Shoe"></div>';
				echo '          <img src="../', $item['Image_URL'], '" alt="Shoe" style="max-height:188px;">';
				echo '  </td>';
				#echo '          </div>';
				#echo '        </div>';
				#echo '        <div class="col-sm-4">';
				echo '  <td align="center">';
				echo  	        $item['Name'];
				#echo '        </div>';
				#echo '      </div>';
				#echo '    </div>';
				echo '  </td>';
				echo '  <td align="center">', money_format('%.2n', $item['Price']), '</td>';
				echo '  <td align="center">';
				echo            $quantity;
				#echo '          <form class="form-inline marginalbot" method="post" action="/cart/">';
				//echo '          <div class="form-group"">';
				//echo '          <div class="col-xs-3">';
				#echo '          <input type="text" name="q" size="2" class="form-control" value="', $quantity ,'" />';
				//echo '          </div>';
				//echo '          </div>';
				#echo '          </form>';
				echo '  </td>';
				echo '  <td align="center">', money_format('%.2n', $subtotal), '</td>';
				echo '</tr>';
			}
			$i++;
		}
	}
	echo '  </tbody>';
	echo '  <tfoot>';
	$totalStr = money_format('%.2n', $total);

	echo '    <tr>';
	#echo '      <td colspan="4"</td>';
	#echo '      </td>';
	echo '      <td colspan="5" class="total" style="padding-right:30px;">Total ', $totalStr, '</td>';
	/*
	echo '      <td>';
	if (isset($_SESSION['name'])) {
		echo '          <form class="form-inline" method="post" action="/new-checkout/">';
		echo '          <input type="hidden" name="checkout" value="1" />';
		echo '          <button type="submit" class="btn btn-success"';
		if ($emptycart == true) {
			echo ' disabled';
		}
		echo '          >Checkout</button>';
		echo '          </form>';
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
	*/
	#echo '    <td colspan="2"</td>';
	echo '    </tr>';
	echo '  </tfoot>';
	echo '</table>';

        echo '<hr class="mb-4">';

	echo '    </div>'; #end of first table col

	echo '    <div class="col-sm-3" style="position: sticky !important; top:0;">';
	echo '      <br/>';
	echo '      <div class="jumbotron text-center" style="padding-right:10px; padding-left:10px; padding-top:20px; padding-bottom:20px; margin-top:18px;">';
	echo '        <h3 style="margin-top:10px;"><b>Total ', $totalStr, '</b></h3>';
        echo '        <h3 class="mb-3">Quickly check out with:</h3>';
        echo '        <form class="needs-validation" method="post" id="submitform" action="/purchase/" novalidate>';
        echo '          <input class="btn btn-primary" type="image" src="../securely_checkout.png" id="secure_purchase" width="240" height="136"/>';
        echo '        </form>';
	echo '      </div>';
	echo '    </div>';


        echo '  </div>';
	echo '</div>';
	echo '<br/><br/>';

}


checkout();
if (isset($_POST['confirm'])) {
	showCart();
}

else{

?>
<!--<script src="myscript.js"></script>-->

<div class="container">
	<div class="row">
		<div class="col-md-3" style="width:29.16666667%;"></div> <!-- col-md-3.5 -->
		<div class="col-md-1" align="center" style="padding-right:0px; padding-left:0px; padding-top:45px;">
			<div class="circle-current" style="margin-left:0px; margin-right:0px;">1</div>
			<div class="text-current">Shipping</div>
		</div>
		<div class="col-md-1" style="padding-right:0px; padding-left:0px;">
			<div style="font-size:90px; text-align:center;">---</div>
		</div>
		<div class="col-md-1" align="center" style="padding-right:0px; padding-left:0px; padding-top:45px;">
			<div class="circle-incomplete">2</div>
			<div class="text-incomplete">Billing</div>
		</div>
		<div class="col-md-1" style="padding-right:0px; padding-left:0px;">
			<div style="font-size:90px; text-align:center;">---</div>
		</div>
		<div class="col-md-1" align="center" style="padding-right:0px; padding-left:0px; padding-top:45px;">
			<div class="circle-incomplete">3</div>
			<div class="text-incomplete">Order Complete!</div>
		</div>
		<div class="col-md-3" style="width:29.16666667%;"></div> <!-- col-md-3.5 -->

	</div>
	<br/>
	
	<div class="row">
		<div>
		</div>
		<div class="col-md-8 col-md-offset-2">
			<form class="needs-validation" method="post" id="submitform" novalidate>
			<h3 class="mb-4">Shipping address</h3>
					<div style="border-style:solid;padding:10px;border-width:2px;border-color:gray;border-width-bottom:0px;">
				        	<input type="radio" class="custom-control-input" id="same-address" name="address" checked="false" onchange="checkBothPurchase();">
						<label class="custom-control-label" for="same-address" style="font:normal 20px times !important;">Use your billing address as the shipping address </label>
			                </div>
					<div  style="border-style:solid;padding:10px;border-width:2px;border-color:gray;">
						<input type="radio" class="custom-control-input" id="different-address" name="address" onchange="checkBothPurchase();">
						<label class="custom-control-label" for="different-address" style="font:normal 20px times !important;">Input new shipping address </label>
				<div id = "shippingInfo" style="display:none">
					<div class="row">
						<div class="col-md-6 mb-3">
							<label for="firstName">First name</label>
							<input type="text" class="form-control" id="firstName" name="firstName" placeholder="" value=""  onchange="checkBothPurchase();" required>
						</div>
						<div class="col-md-6 mb-3">
							<label for="lastName">Last name</label>
							<input type="text" class="form-control" id="lastName" name="lastName" placeholder="" value=""  onchange="checkBothPurchase();" required>
						</div>
					</div>

					<div class="mb-3">
						<label for="address">Address</label>
						<input type="text" class="form-control" id="address" name="address" placeholder="1234 Main St"  onchange="checkBothPurchase();" required>
					</div>

					<div class="mb-3">
						<label for="address2">Address 2 <span class="text-muted">(Optional)</span></label>
						<input type="text" class="form-control" id="address2" name="address2" placeholder="Apartment or suite">
					</div>

					<div class="row">
						<div class="col-md-2 mb-3">
							<label for="country">Country</label>
							<select class="form-control" id="country" name="country" onchange="checkBothPurchase();" required>
								<option value="">...</option>
								<option>US</option>
							</select>
						</div>
						<div class="col-md-3 mb-3">
							<label for="state">State</label>
							<select class="form-control" id="state" name="state" onchange="checkBothPurchase();" required>
								<option value="">Choose...</option>
								<option>California</option>
							</select>
						</div>
						<div class="col-md-3 mb-3">
							<label for="city">City</label>
							<input type="text" class="form-control" id="city" name="city" placeholder=""  onchange="checkBothPurchase();" required>
						</div>
						<div class="col-md-3 mb-3">
							<label for="zip">Zip</label>
							<input type="text" class="form-control" id="zip" name="zip" placeholder=""  onchange="checkBothPurchase();" required>
						</div>
					</div>
				</div>
				</div>
				<br>

				<form method="post" action="/new-checkout/">
                                  <input type="hidden" name="confirm" value="y" />
				  <div align="center">
				    <button type="submit" class="btn btn-primary btn-lg" id="goto_confirm"><font size="5">Billing and Confirm</font></button>
                                  </div>
                                </form>


                                <!--
				<hr class="mb-4">

				<h3 class="mb-4">Billing Information</h3>
				<div class="text-center">
					<h4 class="mb-3">Quickly check out with:</h4>		
					<input class="btn btn-primary" type="image" src="../visa_checkout.png" id="secure_purchase" width="240" height="136"/>-->
					<!--<h2 class="mb-3"> OR</h2>-->
					<!--<div class="btn mb-3" id="normal_checkout" style="color:blue; text-decoration:underline; -webkit-text-decoration-color:blue; text-decoration-color:blue;font-size:23px;">checkout normally </div>-->
				<!--</div>-->


				<!--
				<div id="billingInfo" style="display:none">
				<h3 class="mb-4">Billing address</h3>
				<div class="row">
					<div class="col-md-6 mb-3">
						<label for="firstName">First name</label>
						<input type="text" class="form-control" id="firstNameBilling" name="firstNameBilling" placeholder="" value="" onchange="checkBothPurchase();" required>
					</div>
					<div class="col-md-6 mb-3">
						<label for="lastName">Last name</label>
						<input type="text" class="form-control" id="lastNameBilling" name="lastNameBilling" placeholder="" value="" onchange="checkBothPurchase();" required>
					</div>
				</div>

				<div class="mb-3">
					<label for="address">Address</label>
					<input type="text" class="form-control" id="addressBilling" name="addressBilling" placeholder="1234 Main St" onchange="checkBothPurchase();" required>
				</div>

				<div class="mb-3">
					<label for="address2">Address 2 <span class="text-muted">(Optional)</span></label>
					<input type="text" class="form-control" id="address2Billing" name="address2Billing" placeholder="Apartment or suite">
				</div>

				<div class="row">
					<div class="col-md-2 mb-3">
						<label for="country">Country</label>
						<select class="form-control" id="countryBilling" name="countryBilling" onchange="checkBothPurchase();" required>
							<option value="">...</option>
							<option>US</option>
						</select>
					</div>
					<div class="col-md-3 mb-3">
						<label for="state">State</label>
						<select class="form-control" id="stateBilling" name="stateBilling" onchange="checkBothPurchase();" required>
							<option value="">Choose...</option>
							<option>California</option>
						</select>
					</div>
					<div class="col-md-3 mb-3">
						<label for="city">City</label>
						<input type="text" class="form-control" id="cityBilling" name="cityBilling" placeholder="" onchange="checkBothPurchase();" required>
					</div>
					<div class="col-md-3 mb-3">
						<label for="zip">Zip</label>
						<input type="text" class="form-control" id="zipBilling" name="zipBilling" placeholder="" onchange="checkBothPurchase();" required>
					</div>
				</div>
								 
				<h3 class="mp-4 mt-3">Payment</h3>

				<div class="row">
					<div class="col-md-6 mb-3">
						<label for="cc-name">Name on card</label>
						<input type="text" class="form-control" id="cc-name" name="cc-name" placeholder="" onchange="checkBothPurchase();" required>
						<small class="text-muted">Full name as displayed on card</small>
					</div>
					<div class="col-md-6 mb-3">
						<label for="cc-number">Credit card number</label>
						<input type="text" class="form-control" id="cc-number" name="cc-number" placeholder="" onchange="checkBothPurchase();" required>
					</div>
				</div>
				<div class="row">
					<div class="col-md-3 mb-3">
						<label for="cc-expiration">Expiration</label>
						<input type="text" class="form-control" id="cc-expiration" name="cc-expiration" placeholder="" onchange="checkBothPurchase();" required>
					</div>
					<div class="col-md-3 mb-3">
						<label for="cc-expiration">CVV</label>
						<input type="text" class="form-control" id="cc-cvv" name="cc-cvv" placeholder="" onchange="checkBothPurchase();" required>
					</div>
				</div>
				-->
				
				
				<br>
				<hr class="mb-4">
				<!--<button class="btn btn-primary btn-lg btn-block" name="purchase" type="submit">Purchase</button>-->
				<!--<input class="btn btn-primary btn-lg btn-block" type="submit" id="submitBtn" value="Purchase" disabled="disabled">-->
				</div>
				<input type="hidden" id="purchase" name="purchase" value="success" />
			</form>
		</div>
	</div>
</div><br /><br />

<?php
}
?>

<script>
$('#firstName, #lastName, #address, #address2, #country, #state, #city, #zip, #firstNameBilling, #lastNameBilling, #addressBilling, #address2Billing, #countryBilling, #stateBilling, #cityBilling, #zipBilling, #cc-name, #cc-number, #cc-expiration, #cc-cvv').bind('keyup', checkPurchase());
$('#firstName, #lastName, #address, #address2, #country, #state, #city, #zip, #firstNameBilling, #lastNameBilling, #addressBilling, #address2Billing, #countryBilling, #stateBilling, #cityBilling, #zipBilling, #cc-name, #cc-number, #cc-expiration, #cc-cvv').bind('click', checkPurchase());
$('#firstName, #lastName, #address, #address2, #country, #state, #city, #zip').bind('keyup',  checkQuickPurchase ());
$('#firstName, #lastName, #address, #address2, #country, #state, #city, #zip').bind('click', checkQuickPurchase ());

document.getElementById("secure_purchase").onclick = function() {
	$("#submitform").attr('action', '/purchase/');
	document.getElementById("submitform").submit();
};

document.getElementById("normal_checkout").onclick = function() {
	$("#billingInfo").removeAttr("style");
	$("#normal_checkout").css("display", "none");
	console.log("billing button pressed");
};
function checkPurchase() {
	if(allFilled()) {
                $('#submitBtn').removeAttr('disabled');
        } else {
                console.log("nopurch");
                $('#submitBtn').attr('disabled', 'disabled');
        }
}

function checkQuickPurchase() {
	if(shippingFilled()) {
                $('#goto_confirm').removeAttr('disabled');
        } else {
                console.log("noship");
                $('#goto_confirm').attr('disabled', 'disabled');
        }
}

function checkBothPurchase() {
	checkPurchase();
	checkQuickPurchase();
}

function allFilled() {
	return (shippingFilled() && billingFilled());
}

function billingFilled() {
	var filled = true;
	$('#firstNameBilling, #lastNameBilling, #addressBilling, #countryBilling, #stateBilling, #cityBilling, #zipBilling, #cc-name, #cc-number, #cc-expiration, #cc-cvv').each(function() {
        if($(this).val() == '') filled = false;
	});
	return filled;

}
function shippingFilled() {
	var filled = true;
	$('#firstName, #lastName, #address, #country, #state, #city, #zip').each(function() {
		if($(this).val() == '') filled = false;
	});
	if(document.getElementById("same-address").checked){
		filled = true;
		$("#shippingInfo").css("display", "none");
	} 
	//else if(document.getElementById("different-address").checked){
	else {
		$("#shippingInfo").removeAttr("style");
	}
	return filled;
}

</script>

<?php
	require('../footer.php');
?>
