<?php
	if(isset($_POST) && isset($_SERVER['SSA_ID']) ){
?>

<html>
    <body onload="document.forms[0].submit()">
        <form action="/new-checkout/" method="post">
                <input type="hidden" name="purchase" value="success">
        </form>
    </body>
</html>
<?php
	}else{
	?>
<html>
    <body onload="document.forms[0].submit()">
        <form action="/new-checkout/" method="post">
                <input type="hidden" name="purchase" value="failed">
        </form>
    </body>
</html>
	

	<?php
	}
?>



