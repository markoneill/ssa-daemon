<?php 
session_start();
ini_set('display_errors', 'On');
error_reporting(E_ALL);
require('items.php');
require('header.php');

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
