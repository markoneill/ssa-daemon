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

checkout();

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
			echo '                           <img class="center animate" src="check5.png" alt="Purchase Complete" width="150" height="150">';
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
		}
	}
	return;
}

?>
<!--<script src="myscript.js"></script>-->
<div class="container">		
	<div class="row">
		<div>
		</div>
		<div class="col-md-8 col-md-offset-2">
			<form class="needs-validation" method="post" id="submitform" novalidate>
			<h3 class="mb-4">Shipping address</h3>
					<div style="border-style:solid;padding:10px;border-width:2px;border-color:gray;border-width-bottom:0px;">
				        	<input type="radio" class="custom-control-input" id="same-address" name="address" checked="true" onchange="checkBothPurchase();">
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
				<hr class="mb-4">

				<h3 class="mb-4">Billing Information</h3>
				<div class="text-center">
					<h4 class="mb-3">Quickly check out with:</h4>		
					<input class="btn btn-primary" type="image" src="../visa_checkout.png" id="secure_purchase" width="240" height="136"/>
					<!--<h2 class="mb-3"> OR</h2>-->
					<!--<div class="btn mb-3" id="normal_checkout" style="color:blue; text-decoration:underline; -webkit-text-decoration-color:blue; text-decoration-color:blue;font-size:23px;">checkout normally </div>-->
				</div>


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
                $('#secure_purchase').removeAttr('disabled');
        } else {
                console.log("noship");
                $('#secure_purchase').attr('disabled', 'disabled');
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
	} else {
		$("#shippingInfo").removeAttr("style");
	}
	return filled;
}

</script>

<?php
	require('../footer.php');
?>
