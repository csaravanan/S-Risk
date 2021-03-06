<?php
        /* This Source Code Form is subject to the terms of the Mozilla Public
         * License, v. 2.0. If a copy of the MPL was not distributed with this
         * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

        // Include required functions file
        require_once('../includes/functions.php');
        require_once('../includes/authenticate.php');

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

        // Start the session
	session_set_cookie_params(0, '/', '', isset($_SERVER["HTTPS"]), true);
        session_start('SimpleRisk');

        // Check for session timeout or renegotiation
        session_check();

	// Default is no alert
	$alert = false;

        // Check if access is authorized
        if (!isset($_SESSION["admin"]) || $_SESSION["admin"] != "1")
        {
                header("Location: ../index.php");
                exit(0);
        }
?>

<!doctype html>
<html>
  
  <head>
    <script src="../js/jquery.min.js"></script>
    <script src="../js/bootstrap.min.js"></script>
    <title>FixRisk: Enterprise Risk Management Simplified</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta content="text/html; charset=UTF-8" http-equiv="Content-Type">
    <link rel="stylesheet" href="../css/bootstrap.css">
    <link rel="stylesheet" href="../css/bootstrap-responsive.css"> 
  </head>
  
  <body>
    <?php if ($alert) echo "<script>alert(\"" . $alert_message . "\");</script>" ?>
    <title>FixRisk: Enterprise Risk Management Simplified</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta content="text/html; charset=UTF-8" http-equiv="Content-Type">
    <link rel="stylesheet" href="../css/bootstrap.css">
    <link rel="stylesheet" href="../css/bootstrap-responsive.css">
    <link rel="stylesheet" href="../css/divshot-util.css">
    <link rel="stylesheet" href="../css/divshot-canvas.css">
    <div class="navbar">
      <div class="navbar-inner">
        <div class="container">
            <a class="brand" href="http://www.fixrnix.in/">FixRisk</a>
          <div class="navbar-content">
            <ul class="nav">
              <li>
                <a href="../index.php">Home</a> 
              </li>
              <li>
                <a href="../management/index.php">Risk Management</a> 
              </li>
              <li>
                <a href="../reports/index.php">Reporting</a> 
              </li>
              <li class="active">
                <a href="index.php">Configure</a>
              </li>
            </ul>
          </div>
<?php
if (isset($_SESSION["access"]) && $_SESSION["access"] == "granted")
{
          echo "<div class=\"btn-group pull-right\">\n";
          echo "<a class=\"btn dropdown-toggle\" data-toggle=\"dropdown\" href=\"#\">".$_SESSION['name']."<span class=\"caret\"></span></a>\n";
          echo "<ul class=\"dropdown-menu\">\n";
          echo "<li>\n";
          echo "<a href=\"../account/profile.php\">My Profile</a>\n";
          echo "</li>\n";
          echo "<li>\n";
          echo "<a href=\"../logout.php\">Logout</a>\n";
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
        <div class="span3">
          <ul class="nav  nav-pills nav-stacked">
            <li>
              <a href="index.php">Configure Risk Formula</a> 
            </li>
            <li>
              <a href="review_settings.php">Configure Review Settings</a>
            </li>
            <li>
              <a href="add_remove_values.php">Add and Remove Values</a> 
            </li>
            <li>
              <a href="user_management.php">User Management</a> 
            </li>
            <li>
              <a href="custom_names.php">Redefine Naming Conventions</a> 
            </li>
            <li>
              <a href="audit_trail.php">Audit Trail</a>
            </li>
            <li class="active">
              <a href="extras.php">Extras</a>
            </li>
            <li>
              <a href="announcements.php">Announcements</a>
            </li>
            <li>
              <a href="about.php">About</a>        
            </li>
          </ul>
        </div>
        <div class="span9">
          <div class="row-fluid">
            <div class="span12">
              <div class="hero-unit">
                <h4>Custom Extras</h4>
                <p>It would be awesome if everything were free, right?  Hopefully the base FixRisk platform is able to serve all of your risk management needs.  But, if you find yourself still wanting more functionality, I've developed a series of &quot;Extras&quot; that will do just that for just a few hundred bucks each (perpetual use license).
                </p>
                <ul>
                  <li><b>Custom Authentication Extra:</b> Currently provides support for Active Directory Authentication, but will have other custom authentication types in the future.</li>
                  <li><b>Team Based Separation Extra:</b> Restriction of risk viewing to team members the risk is categorized as.</li>
                  <li><b>Notification Extra:</b> Email notifications when risks are updated or due for action.</li>
                  <li><b>Encrypted Database Extra:</b> Encryption of sensitive text fields in the database.</li>
                </ul>
                <p>If you are interested in adding these or other custom functionality to your FixRisk installation, please send an e-mail to <a href="mailto:shan@fixrnix.in?Subject=Interest%20in%20SimpleRisk%20Extras" target="_top">shan@fixrnix.in</a>.</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </body>

</html>
