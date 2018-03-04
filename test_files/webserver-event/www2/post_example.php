<?php
        session_start();
        if (!isset($_SESSION['logged_in'])) $_SESSION['logged_in'] = FALSE;
        $loginAttempt = FALSE;
        if (isset($_POST['username']) && isset($_POST['password'])) {
                $loginAttempt = TRUE;
                $username = $_POST['username'];
                $password = $_POST['password'];


                $_SESSION['logged_in'] = FALSE;
                if ($username == "bob" && $password == "pass") {
                        $_SESSION['logged_in'] = TRUE;
                }
        }
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <title>POST Example</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">
  <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.1.1/jquery.min.js"></script>
  <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>
</head>
<body>
  <div class="jumbotron text-center">
    <h1>Webserver POST Test</h1>
  </div>
  <div class="container">
    <div class="row">
      <div class="col-sm-12">
        <h1>Member's Area</h1>
<?php
        if ($loginAttempt && $_SESSION['logged_in'] == FALSE) {
                echo '<p>Incorrect credentials</p>';
        }
        else if ($_SESSION['logged_in']) {
                echo "<p>Welcome, Bob.  The member's secret is 42</p>";
        }
        else {
                echo "<p>You haven't tried to log in</p>";
        }
?>
      </div>
    </div>
    <div class="row">
      <div class="col-sm-12">
        <h1>Debug Information (post variables)</h1>
        <p><?php print_r($_POST); ?></p>
      </div>
    </div>
  </div>
</body>
</html>

