
<?php
session_start();
//session_start();
require('../items.php');


updateItems();
showUpdatedCart();

function showUpdatedCart() {
	//session_start();
	
        setlocale(LC_MONETARY, 'en_US.UTF-8');
        //$sid = session_id();
        //session_start($sid);
        global $items;
	$categories = array_keys($items);
	echo '<font size="4" face="Courier New">';
        echo '<table class="table table-striped" width="100%">';
        echo '  <thead>';
        echo '    <tr>';
        echo '      <th><font size="5">Item</font></th>';
        echo '      <th><font size="5">Unit Price</font></th>';
        echo '      <th><font size="5">Quantity</font></th>';
        echo '      <th><font size="5">Subtotal</font></th>';
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
                                echo '  <td><font size="4">', $item['Name'], '</font></td>';
                                echo '  <td><font size="4">', money_format('%.2n', $item['Price']), '</font></td>';
                                echo '  <td><font size="4">', $quantity, '</font></td>';
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
                                echo '  <td><font size="4">', money_format('%.2n', $subtotal), '</font></td>';
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
        echo '      <td colspan="4" class="total"><font size="4">Total: ', $totalStr, '</font></td>';
        /*
        echo '      <td>';
        echo '      </td>';
         */
        echo '    </tr>';
        echo '  </tfoot>';
	echo '</table>';
	echo '</font>';
}

     
function updateItems() {

        //$_POST = array();
        //console.log("update");

        ///*

        //console.log($_POST['s']);
        //console.log($_POST['p']);
        //console.log("updatecart");
        if (!isset($_POST['s']) || !isset($_POST['p'])) {
                return;
        }
        //console.log("itemupdated");

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


        //echo '<script>';
        //echo 'document.getElementById(\'modal-wrapper\').style.display=\'block\';';
        //echo '</script>';

	//showUpdatedCart();

        return;
        // */
}

?>

