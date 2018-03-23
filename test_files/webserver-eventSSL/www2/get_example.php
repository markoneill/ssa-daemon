<?php

        $greeting = '';
        if (isset($_GET['name']) && isset($_GET['color'])) {
                $color = $_GET['color'] == 'blue' ? 'blue' : 'lame';
                $greeting = "Hello {$_GET['name']}! Your favorite color is {$color}";
        }

?>
<!DOCTYPE html>
<html lang="en">
<head>
  <title>GET Example</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.1/jquery.min.js"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
</head>
<body>
  <div class="jumbotron text-center">
    <h1>Webserver GET Test</h1>
  </div>
  <div class="container">
    <div class="row">
      <div class="col-sm-12">
        <p><?php echo $greeting; ?></p>
      </div>
    </div>
  </div>
</body>
</html>
