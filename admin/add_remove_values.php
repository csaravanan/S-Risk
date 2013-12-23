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

        // Check if a new category was submitted
        if (isset($_POST['add_category']))
        {
                $name = $_POST['new_category'];

                // Insert a new category up to 50 chars
                add_name("category", $name, 50);

                // Audit log
                $risk_id = 1000;
                $message = "A new category was added by the \"" . $_SESSION['user'] . "\" user.";
                write_log($risk_id, $_SESSION['uid'], $message);

		// There is an alert message
		$alert = true;
		$alert_message = "A new category was added successfully.";
        }

        // Check if a category was deleted
        if (isset($_POST['delete_category']))
        {
                $value = (int)$_POST['category'];

                // Verify value is an integer
                if (is_int($value))
                {
                        delete_value("category", $value);

                	// Audit log
                	$risk_id = 1000;
                	$message = "An existing category was removed by the \"" . $_SESSION['user'] . "\" user.";
                	write_log($risk_id, $_SESSION['uid'], $message);

                	// There is an alert message
                	$alert = true;
                	$alert_message = "An existing category was removed successfully.";
                }
        }

        // Check if a new team was submitted
        if (isset($_POST['add_team']))
        {
                $name = $_POST['new_team'];

                // Insert a new team up to 50 chars
                add_name("team", $name, 50);

                // Audit log
                $risk_id = 1000;
                $message = "A new team was added by the \"" . $_SESSION['user'] . "\" user.";
                write_log($risk_id, $_SESSION['uid'], $message);

                // There is an alert message
                $alert = true;
                $alert_message = "A new team was added successfully.";
        }

        // Check if a team was deleted
        if (isset($_POST['delete_team']))
        {
                $value = (int)$_POST['team'];

                // Verify value is an integer
                if (is_int($value))
                {
                        delete_value("team", $value);

                        // Audit log
                        $risk_id = 1000;
                        $message = "An existing team was removed by the \"" . $_SESSION['user'] . "\" user.";
                        write_log($risk_id, $_SESSION['uid'], $message);

                        // There is an alert message
                        $alert = true;
                        $alert_message = "An existing team was removed successfully.";
                }
        }

        // Check if a new technology was submitted
        if (isset($_POST['add_technology']))
        {
                $name = $_POST['new_technology'];

                // Insert a new technology up to 50 chars
                add_name("technology", $name, 50);

                // Audit log
                $risk_id = 1000;
                $message = "A new technology was added by the \"" . $_SESSION['user'] . "\" user.";
                write_log($risk_id, $_SESSION['uid'], $message);

                // There is an alert message
                $alert = true;
                $alert_message = "A new technology was added successfully.";
        }

        // Check if a technology was deleted
        if (isset($_POST['delete_technology']))
        {
                $value = (int)$_POST['technology'];

                // Verify value is an integer
                if (is_int($value))
                {
                        delete_value("technology", $value);

                        // Audit log
                        $risk_id = 1000;
                        $message = "An existing technology was removed by the \"" . $_SESSION['user'] . "\" user.";
                        write_log($risk_id, $_SESSION['uid'], $message);

                        // There is an alert message
                        $alert = true;
                        $alert_message = "An existing technology was removed successfully.";
                }
        }

        // Check if a new location was submitted
        if (isset($_POST['add_location']))
        {
                $name = $_POST['new_location'];

                // Insert a new location up to 100 chars
                add_name("location", $name, 100);

                // Audit log
                $risk_id = 1000;
                $message = "A new location was added by the \"" . $_SESSION['user'] . "\" user.";
                write_log($risk_id, $_SESSION['uid'], $message);

                // There is an alert message
                $alert = true;
                $alert_message = "A new location was added successfully.";
        }

        // Check if a location was deleted
        if (isset($_POST['delete_location']))
        {
                $value = (int)$_POST['location'];

                // Verify value is an integer
                if (is_int($value))
                {
                        delete_value("location", $value);

                        // Audit log
                        $risk_id = 1000;
                        $message = "An existing location was removed by the \"" . $_SESSION['user'] . "\" user.";
                        write_log($risk_id, $_SESSION['uid'], $message);

                        // There is an alert message
                        $alert = true;
                        $alert_message = "An existing location was removed successfully.";
                }
        }

        // Check if a new planning strategy was submitted
        if (isset($_POST['add_planning_strategy']))
        {
                $name = $_POST['new_planning_strategy'];

                // Insert a new planning strategy up to 20 chars
                add_name("planning_strategy", $name, 20);

                // Audit log
                $risk_id = 1000;
                $message = "A new planning strategy was added by the \"" . $_SESSION['user'] . "\" user.";
                write_log($risk_id, $_SESSION['uid'], $message);

                // There is an alert message
                $alert = true;
                $alert_message = "A new planning strategy was added successfully.";
        }

        // Check if a planning strategy was deleted
        if (isset($_POST['delete_planning_strategy']))
        {
                $value = (int)$_POST['planning_strategy'];

                // Verify value is an integer
                if (is_int($value))
                {
                        delete_value("planning_strategy", $value);

                        // Audit log
                        $risk_id = 1000;
                        $message = "An existing planning strategy was removed by the \"" . $_SESSION['user'] . "\" user.";
                        write_log($risk_id, $_SESSION['uid'], $message);

                        // There is an alert message
                        $alert = true;
                        $alert_message = "An existing planning strategy was removed successfully.";
                }
        }

        // Check if a new close reason was submitted
        if (isset($_POST['add_close_reason']))
        {
                $name = $_POST['new_close_reason'];

                // Insert a new close reason up to 50 chars
                add_name("close_reason", $name, 50);
                
                // Audit log
                $risk_id = 1000;
                $message = "A new close reason was added by the \"" . $_SESSION['user'] . "\" user.";
                write_log($risk_id, $_SESSION['uid'], $message);

                // There is an alert message
                $alert = true;
                $alert_message = "A new close reason was added successfully.";
        }
                        
        // Check if a close reason was deleted
        if (isset($_POST['delete_close_reason']))
        {
                $value = (int)$_POST['close_reason'];
        
                // Verify value is an integer
                if (is_int($value))
                {
                        delete_value("close_reason", $value);
                
                        // Audit log
                        $risk_id = 1000;
                        $message = "An existing close reason was removed by the \"" . $_SESSION['user'] . "\" user.";
                        write_log($risk_id, $_SESSION['uid'], $message);

                        // There is an alert message
                        $alert = true;
                        $alert_message = "An existing close reason was removed successfully.";
                }
        }
?>

<!doctype html>
<html>
  
  <head>
    <script src="../js/jquery.min.js"></script>
    <script src="../js/bootstrap.min.js"></script>
    <title>SimpleRisk: Enterprise Risk Management Simplified</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta content="text/html; charset=UTF-8" http-equiv="Content-Type">
    <link rel="stylesheet" href="../css/bootstrap.css">
    <link rel="stylesheet" href="../css/bootstrap-responsive.css"> 
  </head>
  
  <body>
    <?php if ($alert) echo "<script>alert(\"" . $alert_message . "\");</script>" ?>
    <title>SimpleRisk: Enterprise Risk Management Simplified</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta content="text/html; charset=UTF-8" http-equiv="Content-Type">
    <link rel="stylesheet" href="../css/bootstrap.css">
    <link rel="stylesheet" href="../css/bootstrap-responsive.css">
    <link rel="stylesheet" href="../css/divshot-util.css">
    <link rel="stylesheet" href="../css/divshot-canvas.css">
    <div class="navbar">
      <div class="navbar-inner">
        <div class="container">
          <a class="brand" href="http://www.simplerisk.org/">SimpleRisk</a>
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
            <li class="active">
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
            <li>
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
                <form name="category" method="post" action="">
                <p>
                <h4>Category:</h4>
                Add new category named <input name="new_category" type="text" maxlength="50" size="20" />&nbsp;&nbsp;<input type="submit" value="Add" name="add_category" /><br />
                Delete current category named <?php create_dropdown("category"); ?>&nbsp;&nbsp;<input type="submit" value="Delete" name="delete_category" />
                </p>
                </form>
              </div>
              <div class="hero-unit">
                <form name="team" method="post" action="">
                <p>
                <h4>Team:</h4>
                Add new team named <input name="new_team" type="text" maxlength="50" size="20" />&nbsp;&nbsp;<input type="submit" value="Add" name="add_team" /><br />
                Delete current team named <?php create_dropdown("team"); ?>&nbsp;&nbsp;<input type="submit" value="Delete" name="delete_team" />
                </p>
                </form>
              </div>
              <div class="hero-unit">
                <form name="technology" method="post" action="">
                <p>
                <h4>Technology:</h4>
                Add new technology named <input name="new_technology" type="text" maxlength="50" size="20" />&nbsp;&nbsp;<input type="submit" value="Add" name="add_technology" /><br />
                Delete current technology named <?php create_dropdown("technology"); ?>&nbsp;&nbsp;<input type="submit" value="Delete" name="delete_technology" />
                </p>
                </form>
              </div>
              <div class="hero-unit">
                <form name="location" method="post" action="">
                <p>
                <h4>Site/Location:</h4>
                Add new site/location named <input name="new_location" type="text" maxlength="100" size="20" />&nbsp;&nbsp;<input type="submit" value="Add" name="add_location" /><br />
                Delete current site/location named <?php create_dropdown("location"); ?>&nbsp;&nbsp;<input type="submit" value="Delete" name="delete_location" />
                </p>
                </form>
              </div>
              <div class="hero-unit">
                <form name="planning_strategy" method="post" action="">
                <p>
                <h4>Risk Planning Strategy:</h4>
                Add new risk planning strategy named <input name="new_planning_strategy" type="text" maxlength="20" size="20" />&nbsp;&nbsp;<input type="submit" value="Add" name="add_planning_strategy" /><br />
                Delete current risk planning strategy named <?php create_dropdown("planning_strategy"); ?>&nbsp;&nbsp;<input type="submit" value="Delete" name="delete_planning_strategy" />
                </p>
                </form>
              </div>
              <div class="hero-unit">
                <form name="close_reason" method="post" action="">
                <p>
                <h4>Close Reason:</h4>
                Add new close reason named <input name="new_close_reason" type="text" maxlength="20" size="20" />&nbsp;&nbsp;<input type="submit" value="Add" name="add_close_reason" /><br />
                Delete current close reason named <?php create_dropdown("close_reason"); ?>&nbsp;&nbsp;<input type="submit" value="Delete" name="delete_close_reason" />
                </p>
                </form>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </body>

</html>
