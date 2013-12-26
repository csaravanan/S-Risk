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

        // Check if a new user was submitted
        if (isset($_POST['add_user']))
        {
		// There is an alert message
		$alert = true;

		$type = $_POST['type'];
                $name = addslashes($_POST['name']);
		$email = addslashes($_POST['email']);
                $user = addslashes($_POST['new_user']);
                $pass = $_POST['password'];
                $repeat_pass = $_POST['repeat_password'];
		$teams = $_POST['team'];
                $admin = isset($_POST['admin']) ? '1' : '0';
		$submit_risks = isset($_POST['submit_risks']) ? '1' : '0';
		$modify_risks = isset($_POST['modify_risks']) ? '1' : '0';
		$plan_mitigations = isset($_POST['plan_mitigations']) ? '1' : '0';
                $review_high = isset($_POST['review_high']) ? '1' : '0';
                $review_medium = isset($_POST['review_medium']) ? '1' : '0';
                $review_low = isset($_POST['review_low']) ? '1' : '0';

		// If the type is 1
		if ($type == "1")
		{
			$type = "simplerisk";
		}
		// If the type is 2
		else if ($type == "2")
		{
			$type = "ldap";
		}
		else $type = "INVALID";

                // Verify that the two passwords are the same
                if ("$pass" == "$repeat_pass")
                {
                        // Verify that the user does not exist
                        if (!user_exist($user))
                        {
				// Generate the salt
				$salt = generateSalt($user);

				// Generate the password hash
				$hash = generateHash($salt, $pass);

				// Create a boolean for all
				$all = false;

				// Create a boolean for none
				$none = false;

				// Create the team value
				foreach ($teams as $value)
				{
					// If the selected value is all
					if ($value == "all") $all = true;

					// If the selected value is none
					if ($value == "none") $none = true;

					$team .= ":";
					$team .= $value;
					$team .= ":";
				}

				// If no value was submitted then default to none
				if ($value == "") $none = true;

				// If all was selected then assign all teams
				if ($all) $team = "all";

				// If none was selected then assign no teams
				if ($none) $team = "none";

                                // Insert a new user
                                add_user($type, $user, $email, $name, $hash, $team, $admin, $review_high, $review_medium, $review_low, $submit_risks, $modify_risks, $plan_mitigations);

                        	// Audit log
                        	$risk_id = 1000;
                        	$message = "A new user was added by the \"" . $_SESSION['user'] . "\" user.";
                        	write_log($risk_id, $_SESSION['uid'], $message);

				$alert_message = "The new user was added successfully.";
                        }
			// Otherwise, the user already exists
			else $alert_message = "The username already exists.  Please try again with a different username.";
                }
		// Otherewise, the two passwords are different
		else $alert_message = "The password and repeat password entered were different.  Please try again.";
        }

	// Check if a user was enabled
	if (isset($_POST['enable_user']))
	{
                $value = (int)$_POST['disabled_users'];

                // Verify value is an integer
                if (is_int($value))
                {
                        enable_user($value);

                        // Audit log
                        $risk_id = 1000;
                        $message = "A user was enabled by the \"" . $_SESSION['user'] . "\" user.";
                        write_log($risk_id, $_SESSION['uid'], $message);

                        // There is an alert message
                        $alert = true;
                        $alert_message = "The user was enabled successfully.";
                }
	}

	// Check if a user was disabled
	if (isset($_POST['disable_user']))
	{
                $value = (int)$_POST['enabled_users'];

                // Verify value is an integer
                if (is_int($value))
                {
                        disable_user($value);

                        // Audit log
                        $risk_id = 1000;
                        $message = "A user was disabled by the \"" . $_SESSION['user'] . "\" user.";
                        write_log($risk_id, $_SESSION['uid'], $message);

                        // There is an alert message
                        $alert = true;
                        $alert_message = "The user was disabled successfully.";
                }

	}

        // Check if a user was deleted
        if (isset($_POST['delete_user']))
        {
                $value = (int)$_POST['user'];

                // Verify value is an integer
                if (is_int($value))
                {
                        delete_value("user", $value);

                        // Audit log
                        $risk_id = 1000;
                        $message = "An existing user was deleted by the \"" . $_SESSION['user'] . "\" user.";
                        write_log($risk_id, $_SESSION['uid'], $message);

			// There is an alert message
			$alert = true;
			$alert_message = "The existing user was deleted successfully.";
                }
        }

	// Check if a password reset was requeted
        if (isset($_POST['password_reset']))
	{
		$value = (int)$_POST['user'];

                // Verify value is an integer
                if (is_int($value))
                {
                        password_reset_by_userid($value);
              
                        // Audit log
                        $risk_id = 1000;
                       $message = "A password reset request was submitted by the \"" . $_SESSION['user'] . "\" user.";
                        write_log($risk_id, $_SESSION['uid'], $message);


                        // There is an alert message
                        $alert = true;
                        $alert_message = "A password reset email was sent to the user.";
                }
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
    <script type="text/javascript">
      function handleSelection(choice) {
        if (choice=="1") {
          document.getElementById("simplerisk").style.display = "";
        }
        if (choice=="2") {
          document.getElementById("simplerisk").style.display = "none";
        }
      }
    </script>
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
            <li class="active">
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
                <form name="add_user" method="post" action="">
                <p>
                <h4>Add a New User:</h4>
		Type: <select name="type" id="select" onChange="handleSelection(value)">
                <option selected value="1">SimpleRisk</option>
                <option value="2">LDAP</option>
                </select><br />
                Full Name: <input name="name" type="text" maxlength="50" size="20" /><br />
                E-mail Address: <input name="email" type="text" maxlength="200" size="20" /><br />
                Username: <input name="new_user" type="text" maxlength="20" size="20" /><br />
		<div id="simplerisk">
                Password: <input name="password" type="password" maxlength="50" size="20" /><br />
                Repeat Password: <input name="repeat_password" type="password" maxlength="50" size="20" /><br />
		</div>
                <h6><u>Team(s)</u></h6>
                <?php create_multiple_dropdown("team"); ?>
                <h6><u>User Responsibilities</u></h6>
                <ul>
                  <li><input name="submit_risks" type="checkbox" />&nbsp;Able to Submit New Risks</li>
                  <li><input name="modify_risks" type="checkbox" />&nbsp;Able to Modify Existing Risks</li>
                  <li><input name="plan_mitigations" type="checkbox" />&nbsp;Able to Plan Mitigations</li>
                  <li><input name="review_low" type="checkbox" />&nbsp;Able to Review Low Risks</li>
                  <li><input name="review_medium" type="checkbox" />&nbsp;Able to Review Medium Risks</li>
                  <li><input name="review_high" type="checkbox" />&nbsp;Able to Review High Risks</li>
                  <li><input name="admin" type="checkbox" />&nbsp;Allow Access to &quot;Configure&quot; Menu</li>
                </ul>
                <input type="submit" value="Add" name="add_user" /><br />
                </p>
                </form>
              </div>
              <div class="hero-unit">
                <form name="select_user" method="post" action="view_user_details.php">
                <p>
                <h4>View Details for User:</h4>
                View details for user <?php create_dropdown("user"); ?>&nbsp;&nbsp;<input type="submit" value="Select" name="select_user" />
                </p>
                </form>
              </div>
              <div class="hero-unit">
                <form name="enable_disable_user" method="post" action="">
                <p>
                <h4>Enable and Disable Users:</h4>
		Use this feature to enable or disable user logins while maintaining the audit trail of user activities.
		</p>
		<p>
                Disable user <?php create_dropdown("enabled_users"); ?>&nbsp;&nbsp;<input type="submit" value="Disable" name="disable_user" />
                </p>
                <p>
                Enable user <?php create_dropdown("disabled_users"); ?>&nbsp;&nbsp;<input type="submit" value="Enable" name="enable_user" />
                </p>
                </form>
              </div>
              <div class="hero-unit">
                <form name="delete_user" method="post" action="">
                <p>
                <h4>Delete an Existing User:</h4>
                Delete current user <?php create_dropdown("user"); ?>&nbsp;&nbsp;<input type="submit" value="Delete" name="delete_user" />
                </p>
                </form>
              </div>
              <div class="hero-unit">
                <form name="password_reset" method="post" action="">
                <p>
                <h4>Password Reset:</h4>
                Send password reset email for user <?php create_dropdown("user"); ?>&nbsp;&nbsp;<input type="submit" value="Send" name="password_reset" />
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
