<?php
	/* This Source Code Form is subject to the terms of the Mozilla Public
 	 * License, v. 2.0. If a copy of the MPL was not distributed with this
 	 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

        // Include required functions file
        require_once('includes/functions.php');
	require_once('includes/authenticate.php');

        // Add various security headers
        header("X-Frame-Options: DENY");
        header("X-XSS-Protection: 1; mode=block");

        // If we want to enable the Content Security Policy (CSP) - This may break Chrome
        if (CSP_ENABLED == "true")
        {
                // Add the Content-Security-Policy header
                header("Content-Security-Policy: default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'");
        }

	// Session handler is database
	if (USE_DATABASE_FOR_SESSIONS == "true")
	{
		session_set_save_handler('sess_open', 'sess_close', 'sess_read', 'sess_write', 'sess_destroy', 'sess_gc');
	}

	// Start session
	session_set_cookie_params(0, '/', '', isset($_SERVER["HTTPS"]), true);
	session_start('SimpleRisk');

	// If the login form was posted
	if (isset($_POST['submit']))
	{
		$user = $_POST['user'];
		$pass = $_POST['pass'];

		// If the user is valid
		if (is_valid_user($user, $pass))
		{
			$_SESSION["access"] = "granted";

			// Update the last login
			update_last_login($_SESSION['uid']);

                	// Audit log
			$risk_id = 1000;
                	$message = "Username \"" . $_SESSION['user'] . "\" logged in successfully.";
                	write_log($risk_id, $_SESSION['uid'], $message);

			// Redirect to the reports index
			header("Location: reports");
		}
		else $_SESSION["access"] = "denied";
	}
?>

<!doctype html>
<html>
  
  <head>
    <script src="js/jquery.min.js"></script>
    <script src="js/bootstrap.min.js"></script>
    <title>SimpleRisk: Enterprise Risk Management Simplified</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta content="text/html; charset=UTF-8" http-equiv="Content-Type">
    <link rel="stylesheet" href="css/bootstrap.css">
    <link rel="stylesheet" href="css/bootstrap-responsive.css"> 
    <link rel="shortcut icon" href="/favicon.ico" type="image/x-icon">
    <link rel="icon" href="/favicon.ico" type="image/x-icon">
  </head>
  
  <body>
    <title>SimpleRisk: Enterprise Risk Management Simplified</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta content="text/html; charset=UTF-8" http-equiv="Content-Type">
    <link rel="stylesheet" href="css/bootstrap.css">
    <link rel="stylesheet" href="css/bootstrap-responsive.css">
    <link rel="stylesheet" href="css/divshot-util.css">
    <link rel="stylesheet" href="css/divshot-canvas.css">
    <div class="navbar">
      <div class="navbar-inner">
        <div class="container">
          <a class="brand" href="http://www.fixrnix.in/">FixRisk</a>
          <div class="navbar-content">
            <ul class="nav">
              <li class="active">
                <a href="index.php">Home</a> 
              </li>
              <li>
                <a href="management/index.php">Risk Management</a> 
              </li>
              <li>
                <a href="reports/index.php">Reporting</a> 
              </li>
<?php
if (isset($_SESSION["admin"]) && $_SESSION["admin"] == "1")
{
          echo "<li>\n";
          echo "<a href=\"admin/index.php\">Configure</a>\n";
          echo "</li>\n";
}
	  echo "</ul>\n";
          echo "</div>\n";

if (isset($_SESSION["access"]) && $_SESSION["access"] == "granted")
{
          echo "<div class=\"btn-group pull-right\">\n";
          echo "<a class=\"btn dropdown-toggle\" data-toggle=\"dropdown\" href=\"#\">".$_SESSION['name']."<span class=\"caret\"></span></a>\n";
          echo "<ul class=\"dropdown-menu\">\n";
          echo "<li>\n";
          echo "<a href=\"account/profile.php\">My Profile</a>\n";
          echo "</li>\n";
          echo "<li>\n";
          echo "<a href=\"logout.php\">Logout</a>\n";
          echo "</li>\n";
          echo "</ul>\n";
          echo "</div>\n";
}
?>
        </div>
      </div>
    </div>
    <div class="container-fluid">
      <div class="row-fluid">
        <div class="span9">
          <div class="hero-unit">
            <center>
            <img src="images/SimpleRiskLogo.png" style="width:500px;" />
            <p>Enterprise Risk Management Simplified.</p>
            </center>
          </div>
        </div>
      </div>
<?php
if (!isset($_SESSION["access"]) || $_SESSION["access"] != "granted")
{
      echo "<div class=\"row-fluid\">\n";
      echo "<div class=\"span9\">\n";
      echo "<div class=\"well\">\n";
      echo "<p><label><u>Log In Here</u></label></p>\n";
      echo "<form name=\"authenticate\" method=\"post\" action=\"\">\n";
      echo "Username: <input class=\"input-medium\" name=\"user\" id=\"user\" type=\"text\" /><br />\n";
      echo "Password: <input class=\"input-medium\" name=\"pass\" id=\"pass\" type=\"password\" />\n";
      echo "<label><a href=\"reset.php\">Forgot your password?</a></label>\n";
      echo "<div class=\"form-actions\">\n";
      echo "<button type=\"submit\" name=\"submit\" class=\"btn btn-primary\">Login</button>\n";
      echo "<input class=\"btn\" value=\"Reset\" type=\"reset\">\n";
      echo "</div>\n";
      echo "</form>\n";
      echo "</div>\n";
      echo "</div>\n";
      echo "</div>\n";
}
?>
    </div>
  </body>

</html>
