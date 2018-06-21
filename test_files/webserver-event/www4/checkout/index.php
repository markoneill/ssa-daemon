<?php 
session_start();
require('../items.php');
require('../header.php');

checkout();

function checkout() {
	if (isset($_POST['purchase'])) {
		echo '<div class="container">';
		echo '  <div class="row">';
		echo '    <div class="col-md-8 col-md-offset-2">';
		echo '         <h1 class="text-center">Thank You!</h1>';
		echo '         <p class="text-center">Your order has been placed</p>';
		echo '    </div>';
		echo '  </div>';
		echo '</div>';
		session_destroy();
		exit();
	}
	return;
}

?>
<div class="container">    
  <div class="row">
    <div class="col-md-8 col-md-offset-2">
          <h4 class="mb-3">Billing address</h4>
          <form class="needs-validation" method="post" action="" novalidate>
            <div class="row">
              <div class="col-md-6 mb-3">
                <label for="firstName">First name</label>
                <input type="text" class="form-control" id="firstName" placeholder="" value="" required>
              </div>
              <div class="col-md-6 mb-3">
                <label for="lastName">Last name</label>
                <input type="text" class="form-control" id="lastName" placeholder="" value="" required>
              </div>
            </div>

            <div class="mb-3">
              <label for="address">Address</label>
              <input type="text" class="form-control" id="address" placeholder="1234 Main St" required>
            </div>

            <div class="mb-3">
              <label for="address2">Address 2 <span class="text-muted">(Optional)</span></label>
              <input type="text" class="form-control" id="address2" placeholder="Apartment or suite">
            </div>

            <div class="row">
              <div class="col-md-5 mb-3">
                <label for="country">Country</label>
                <select class="form-control" id="country" required>
                  <option value="">Choose...</option>
                  <option>United States</option>
                </select>
              </div>
              <div class="col-md-4 mb-3">
                <label for="state">State</label>
                <select class="form-control" id="state" required>
                  <option value="">Choose...</option>
                  <option>California</option>
                </select>
              </div>
              <div class="col-md-3 mb-3">
                <label for="zip">Zip</label>
                <input type="text" class="form-control" id="zip" placeholder="" required>
              </div>
            </div>
            <hr class="mb-4">
            <div class="custom-control custom-checkbox">
              <input type="checkbox" class="custom-control-input" id="same-address" checked="checked">
              <label class="custom-control-label" for="same-address">Shipping address is the same as my billing address</label>
            </div>
            <hr class="mb-4">

            <h4 class="mb-3">Payment</h4>

            <div class="row">
              <div class="col-md-6 mb-3">
                <label for="cc-name">Name on card</label>
                <input type="text" class="form-control" id="cc-name" placeholder="" required>
                <small class="text-muted">Full name as displayed on card</small>
              </div>
              <div class="col-md-6 mb-3">
                <label for="cc-number">Credit card number</label>
                <input type="text" class="form-control" id="cc-number" placeholder="" required>
              </div>
            </div>
            <div class="row">
              <div class="col-md-3 mb-3">
                <label for="cc-expiration">Expiration</label>
                <input type="text" class="form-control" id="cc-expiration" placeholder="" required>
              </div>
              <div class="col-md-3 mb-3">
                <label for="cc-expiration">CVV</label>
                <input type="text" class="form-control" id="cc-cvv" placeholder="" required>
              </div>
            </div>
            <hr class="mb-4">
            <button class="btn btn-primary btn-lg btn-block" name="purchase" type="submit">Purchase</button>
          </form>
    </div>
  </div>
</div><br /><br />

<?php
	require('../footer.php');
?>
