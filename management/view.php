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
        if (!isset($_SESSION["access"]) || $_SESSION["access"] != "granted")
        {
                header("Location: ../index.php");
                exit(0);
        }

        // Check if a risk ID was sent
        if (isset($_GET['id']))
        {
                $id = htmlentities($_GET['id'], ENT_QUOTES);

                // Get the details of the risk
                $risk = get_risk_by_id($id);

		// If the risk was found use the values for the risk
		if (count($risk) != 0)
		{
                	$status = htmlentities($risk[0]['status'], ENT_QUOTES);
                	$subject = $risk[0]['subject'];
			$reference_id = htmlentities(stripslashes($risk[0]['reference_id']), ENT_QUOTES);
			$location = htmlentities($risk[0]['location'], ENT_QUOTES);
                	$category = htmlentities($risk[0]['category'], ENT_QUOTES);
                	$team = htmlentities($risk[0]['team'], ENT_QUOTES);
                	$technology = htmlentities($risk[0]['technology'], ENT_QUOTES);
                	$owner = htmlentities($risk[0]['owner'], ENT_QUOTES);
                	$manager = htmlentities($risk[0]['manager'], ENT_QUOTES);
                	$assessment = $risk[0]['assessment'];
                	$notes = $risk[0]['notes'];
			$submission_date = htmlentities($risk[0]['submission_date'], ENT_QUOTES);
			$mitigation_id = htmlentities($risk[0]['mitigation_id'], ENT_QUOTES);
			$mgmt_review = htmlentities($risk[0]['mgmt_review'], ENT_QUOTES);
			$calculated_risk = $risk[0]['calculated_risk'];

			$scoring_method = $risk[0]['scoring_method'];
			$CLASSIC_likelihood = $risk[0]['CLASSIC_likelihood'];
			$CLASSIC_impact = $risk[0]['CLASSIC_impact'];
			$AccessVector = $risk[0]['CVSS_AccessVector'];
			$AccessComplexity = $risk[0]['CVSS_AccessComplexity'];
			$Authentication = $risk[0]['CVSS_Authentication'];
			$ConfImpact = $risk[0]['CVSS_ConfImpact'];
			$IntegImpact = $risk[0]['CVSS_IntegImpact'];
			$AvailImpact = $risk[0]['CVSS_AvailImpact'];
			$Exploitability = $risk[0]['CVSS_Exploitability'];
			$RemediationLevel = $risk[0]['CVSS_RemediationLevel'];
			$ReportConfidence = $risk[0]['CVSS_ReportConfidence'];
			$CollateralDamagePotential = $risk[0]['CVSS_CollateralDamagePotential'];
			$TargetDistribution = $risk[0]['CVSS_TargetDistribution'];
			$ConfidentialityRequirement = $risk[0]['CVSS_ConfidentialityRequirement'];
			$IntegrityRequirement = $risk[0]['CVSS_IntegrityRequirement'];
			$AvailabilityRequirement = $risk[0]['CVSS_AvailabilityRequirement'];
		}
		// If the risk was not found use null values
		else
		{
                        $status = "Risk ID Does Not Exist";
                        $subject = "N/A";
                        $reference_id = "N/A";
                        $location = "";
                        $category = "";
                        $team = "";
                        $technology = "";
                        $owner = "";
                        $manager = "";
                        $assessment = "";
                        $notes = "";
                        $submission_date = "";
                        $mitigation_id = "";
                        $mgmt_review = "";
                        $calculated_risk = "0.0";

                        $scoring_method = "";
                        $CLASSIC_likelihood = "";
                        $CLASSIC_impact = "";
                        $AccessVector = "";
                        $AccessComplexity = "";
                        $Authentication = "";
                        $ConfImpact = "";
                        $IntegImpact = "";
                        $AvailImpact = "";
                        $Exploitability = "";
                        $RemediationLevel = "";
                        $ReportConfidence = "";
                        $CollateralDamagePotential = "";
                        $TargetDistribution = "";
                        $ConfidentialityRequirement = "";
                        $IntegrityRequirement = "";
                        $AvailabilityRequirement = "";
		}

		// If the current scoring method is classic and the user requested a change to CVSS
		if (isset($_GET['scoring_method']) && $scoring_method == 1 && htmlentities($_GET['scoring_method'], ENT_QUOTES) == 2)
		{
			// Set the new scoring method
			$scoring_method = change_scoring_method($id, "2");

                        // Audit log
                        $risk_id = $id;
                        $message = "Scoring method was changed for risk ID \"" . $risk_id . "\" by username \"" . $_SESSION['user'] . "\".";
                        write_log($risk_id, $_SESSION['uid'], $message);

                        $alert = true;
                        $alert_message = "The scoring method has been successfully changed to CVSS.";
		}
		// If the current scoring method is CVSS and the user requested a change to classic
		else if (isset($_GET['scoring_method']) && $scoring_method == 2 && htmlentities($_GET['scoring_method'], ENT_QUOTES) == 1)
		{
			// Set the new scoring method
			$scoring_method = change_scoring_method($id, "1");

                        // Audit log
                        $risk_id = $id;
			$message = "Scoring method was changed for risk ID \"" . $risk_id . "\" by username \"" . $_SESSION['user'] . "\".";
                        write_log($risk_id, $_SESSION['uid'], $message);

                        $alert = true;
                        $alert_message = "The scoring method has been successfully changed to Classic.";
		}

                if ($submission_date == "")
                {
                        $submission_date = "N/A";
                }
                else $submission_date = date('Y-m-d g:i A T', strtotime($submission_date));

		// Get the mitigation for the risk
		$mitigation = get_mitigation_by_id($id);

		// If no mitigation exists for this risk
		if ($mitigation == false)
		{
			// Set the values to empty
			$mitigation_date = "N/A";
			$mitigation_date = "";
			$planning_strategy = "";
			$mitigation_effort = "";
			$current_solution = "";
			$security_requirements = "";
			$security_recommendations = "";
		}
		// If a mitigation exists
		else
		{
			// Set the mitigation values
			$mitigation_date = htmlentities($mitigation[0]['submission_date'], ENT_QUOTES);
			$mitigation_date = date('Y-m-d g:i A T', strtotime($mitigation_date));
			$planning_strategy = htmlentities($mitigation[0]['planning_strategy'], ENT_QUOTES);
			$mitigation_effort = htmlentities($mitigation[0]['mitigation_effort'], ENT_QUOTES);
			$current_solution = $mitigation[0]['current_solution'];
			$security_requirements = $mitigation[0]['security_requirements'];
			$security_recommendations = $mitigation[0]['security_recommendations'];
		}

		// Get the management reviews for the risk
		$mgmt_reviews = get_review_by_id($id);

                // If no mitigation exists for this risk
                if ($mgmt_reviews == false)
                {
                        // Set the values to empty
			$review_date = "N/A";
			$review = "";
			$next_step = "";
			$reviewer = "";
			$comments = "";
                }
                // If a mitigation exists
                else
                {
                        // Set the mitigation values
			$review_date = htmlentities($mgmt_reviews[0]['submission_date'], ENT_QUOTES);
			$review_date = date('Y-m-d g:i A T', strtotime($review_date));
			$review = htmlentities($mgmt_reviews[0]['review'], ENT_QUOTES);
			$next_step = htmlentities($mgmt_reviews[0]['next_step'], ENT_QUOTES);
			$reviewer = htmlentities($mgmt_reviews[0]['reviewer'], ENT_QUOTES);
			$comments = $mgmt_reviews[0]['comments'];
		}
        }

	// If the risk details were updated
        if (isset($_POST['update_details']))
        {
		// If the user has permission to modify risks
		if (isset($_SESSION["modify_risks"]) && $_SESSION["modify_risks"] == 1)
		{
                	$subject = addslashes($_POST['subject']);
			$reference_id = addslashes($_POST['reference_id']);
			$location = (int)$_POST['location'];

			// If the scoring method is classic
			if ($scoring_method == 1)
			{
                		$CLASSIC_likelihood = (int)$_POST['likelihood'];
                		$CLASSIC_impact =(int) $_POST['impact'];
			}

			// If the scoring method is CVSS
			if ($scoring_method == 2)
			{
                		$AccessVector = addslashes($_POST['AccessVector']);
                		$AccessComplexity = addslashes($_POST['AccessComplexity']);
                		$Authentication = addslashes($_POST['Authentication']);
                		$ConfImpact = addslashes($_POST['ConfImpact']);
                		$IntegImpact = addslashes($_POST['IntegImpact']);
                		$AvailImpact = addslashes($_POST['AvailImpact']);
                		$Exploitability = addslashes($_POST['Exploitability']);
                		$RemediationLevel = addslashes($_POST['RemediationLevel']);
                		$ReportConfidence = addslashes($_POST['ReportConfidence']);
                		$CollateralDamagePotential = addslashes($_POST['CollateralDamagePotential']);
                		$TargetDistribution = addslashes($_POST['TargetDistribution']);
                		$ConfidentialityRequirement = addslashes($_POST['ConfidentialityRequirement']);
                		$IntegrityRequirement = addslashes($_POST['IntegrityRequirement']);
                		$AvailabilityRequirement = addslashes($_POST['AvailabilityRequirement']);
			}

                	$category = (int)$_POST['category'];
                	$team = (int)$_POST['team'];
                	$technology = (int)$_POST['technology'];
                	$owner = (int)$_POST['owner'];
                	$manager = (int)$_POST['manager'];
                	$assessment = addslashes($_POST['assessment']);
                	$notes = addslashes($_POST['notes']);

			// Update risk
			update_risk($id, $subject, $reference_id, $location, $category, $team, $technology, $owner, $manager, $assessment, $notes);

			// Update the risk score
			$calculated_risk = update_risk_scoring($id, $scoring_method, $CLASSIC_likelihood, $CLASSIC_impact, $AccessVector, $AccessComplexity, $Authentication, $ConfImpact, $IntegImpact, $AvailImpact, $Exploitability, $RemediationLevel, $ReportConfidence, $CollateralDamagePotential, $TargetDistribution, $ConfidentialityRequirement, $IntegrityRequirement, $AvailabilityRequirement);

                	// Audit log
                	$risk_id = $id;
                	$message = "Risk details were updated for risk ID \"" . $risk_id . "\" by username \"" . $_SESSION['user'] . "\".";
                	write_log($risk_id, $_SESSION['uid'], $message);

			$alert = true;
			$alert_message = "The risk has been successfully modified.";
		}
		// Otherwise, the user did not have permission to modify risks
		else
		{
			$alert = true;
                	$alert_message = "You do not have permission to modify risks.  Your attempt to modify the details of this risk was not recorded.  Please contact an Administrator if you feel that you have reached this message in error.";
		}
        }

	// If the user has selected to edit the risk details and does not have permission
	if ((isset($_POST['edit_details'])) && ($_SESSION['modify_risks'] != 1))
	{
        	$alert = true;
                $alert_message = "You do not have permission to modify risks.  Any risks that you attempt to modify will not be recorded.  Please contact an Administrator if you feel that you have reached this message in error.";
	}

	// Check if a mitigation was updated
	if (isset($_POST['update_mitigation']))
	{
                $planning_strategy = (int)$_POST['planning_strategy'];
		$mitigation_effort = (int)$_POST['mitigation_effort'];
                $current_solution = addslashes($_POST['current_solution']);
                $security_requirements = addslashes($_POST['security_requirements']);
                $security_recommendations = addslashes($_POST['security_recommendations']);

		// If we don't yet have a mitigation
		if ($mitigation_id == 0)
		{
	                $status = "Mitigation Planned";

                	// Submit mitigation and get the mitigation date back
                	$mitigation_date = submit_mitigation($id, $status, $planning_strategy, $mitigation_effort, $current_solution, $security_requirements, $security_recommendations);
			$mitigation_date = date('Y-m-d g:i A T', strtotime($mitigation_date));
		}
		else
		{
			// Update mitigation and get the mitigation date back
			$mitigation_date = update_mitigation($id, $planning_strategy, $mitigation_effort, $current_solution, $security_requirements, $security_recommendations);
			$mitigation_date = date('Y-m-d g:i A T', strtotime($mitigation_date));
		}

                // Audit log
                $risk_id = $id;
                $message = "Risk mitigation details were updated for risk ID \"" . $risk_id . "\" by username \"" . $_SESSION['user'] . "\".";
                write_log($risk_id, $_SESSION['uid'], $message);

		$alert = true;
		$alert_message = "The risk mitigation has been successfully modified.";
	}

	// If comment is passed via GET
	if (isset($_GET['comment']))
	{
		// If it's true
		if ($_GET['comment'] == true)
		{
			$alert = true;
			$alert_message = "Your comment has been successfully added to the risk.";
		}
	}

        // If closed is passed via GET
        if (isset($_GET['closed']))
        {       
                // If it's true
                if ($_GET['closed'] == true)
                {
                        $alert = true;
                        $alert_message = "Your risk has now been marked as closed.";
                }
        }

        // If reopened is passed via GET
        if (isset($_GET['reopened']))
        {       
                // If it's true
                if ($_GET['reopened'] == true)
                {       
                        $alert = true; 
                        $alert_message = "Your risk has now been reopened.";      
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
    <link rel="stylesheet" href="../css/divshot-util.css">
    <link rel="stylesheet" href="../css/divshot-canvas.css">
  </head>
  
  <body>
    <?php if ($alert) echo "<script>alert(\"" . $alert_message . "\");</script>"; ?>
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
              <li class="active">
                <a href="index.php">Risk Management</a> 
              </li>
              <li>
                <a href="../reports/index.php">Reporting</a> 
              </li>
<?php
if (isset($_SESSION["admin"]) && $_SESSION["admin"] == "1")
{
          echo "<li>\n";
          echo "<a href=\"../admin/index.php\">Configure</a>\n";
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
              <a href="index.php">I. Submit Your Risks</a> 
            </li>
            <li>
              <a href="plan_mitigations.php">II. Plan Your Mitigations</a> 
            </li>
            <li>
              <a href="management_review.php">III. Perform Management Reviews</a> 
            </li>
            <li>
              <a href="prioritize_planning.php">IV. Prioritize for Project Planning</a> 
            </li>
            <li class="active">
              <a href="review_risks.php">V. Review Risks Regularly</a>
            </li>
          </ul>
        </div>
        <div class="span9">
          <div class="row-fluid">
            <div class="well">
              <div class="btn-group pull-right">
                <a class="btn dropdown-toggle" data-toggle="dropdown" href="#">Action<span class="caret"></span></a>
                <ul class="dropdown-menu">
             	<?php 
			// If the risk is closed, offer to reopen
                    	if ($status == "Closed")
                    	{
                      		echo "<li><a href=\"reopen.php?id=".$id."\">Reopen Risk</a></li>\n";
			}
			// Otherwise, offer to close
			else
			{
				echo "<li><a href=\"close.php?id=".$id."\">Close Risk</a></li>\n";
			}

			// If the risk is classic scoring
			if ($scoring_method == 1)
			{
				echo "<li><a href=\"view.php?id=".$id."&scoring_method=2\">Score by CVSS</a></li>\n";
			}
			// If the risk is CVSS scoring
			else if ($scoring_method == 2)
			{
				echo "<li><a href=\"view.php?id=".$id."&scoring_method=1\">Score by Classic</a></li>\n";
			}

			// If the risk is unmitigated, offer mitigation option
			if ($mitigation_id == 0)
			{
				echo "<li><a href=\"mitigate.php?id=".$id."\">Plan a Mitigation</a></li>\n";
			}
		?>
                  <li><a href="mgmt_review.php?id=<?php echo $id; ?>">Perform a Review</a></li>
                  <li><a href="comment.php?id=<?php echo $id; ?>">Add a Comment</a></li>
                </ul>
              </div>
              <h4><u>View Risk Details</u></h4>
              <h4>Risk ID: <?php echo $id ?></h4>
              <h4>Subject: <?php echo htmlentities(stripslashes($subject)); ?></h4>
              <h4>Calculated Risk: <?php echo $calculated_risk . " (". get_risk_level_name($calculated_risk) . ")"; ?></h4>
<?php
	if ($scoring_method == "2")
	{
		echo "<h4>CVSS Base Vector: AV:" . htmlentities(stripslashes($AccessVector), ENT_QUOTES) . "/AC:" . htmlentities(stripslashes($AccessComplexity), ENT_QUOTES) . "/Au:" . htmlentities(stripslashes($Authentication), ENT_QUOTES) . "/C:" . htmlentities(stripslashes($ConfImpact), ENT_QUOTES) . "/I:" . htmlentities(stripslashes($IntegImpact), ENT_QUOTES) . "/A:" . htmlentities(stripslashes($AvailImpact), ENT_QUOTES) . "</h4>\n";
		echo "<h4>CVSS Temporal Vector: E:" . htmlentities(stripslashes($Exploitability), ENT_QUOTES) . "/RL:" . htmlentities(stripslashes($RemediationLevel), ENT_QUOTES) . "/RC:" . htmlentities(stripslashes($ReportConfidence), ENT_QUOTES) . "</h4>\n";
		echo "<h4>CVSS Environmental Vector: CDP:" . htmlentities(stripslashes($CollateralDamagePotential), ENT_QUOTES) . "/TD:" . htmlentities(stripslashes($TargetDistribution), ENT_QUOTES) . "/CR:" . htmlentities(stripslashes($ConfidentialityRequirement), ENT_QUOTES) . "/IR:" . htmlentities(stripslashes($IntegrityRequirement), ENT_QUOTES) . "/AR:" . htmlentities(stripslashes($AvailabilityRequirement), ENT_QUOTES) . "</h4>\n";
	}
?>
              <h4>Status: <?php echo $status ?></h4>
            </div>
          </div>
          <div class="row-fluid">
            <form name="submit_risk" method="post" action="">
            <div class="span4">
              <div class="well">
                <h4>Details</h4>
<?php
// If the user has selected to edit the risk
if (isset($_POST['edit_details']))
{
        echo "Submission Date: \n";
        echo "<input type=\"text\" name=\"submission_date\" id=\"submission_date\" size=\"50\" value=\"" . htmlentities($submission_date, ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
        echo "<br />\n";
        echo "Subject: <input type=\"text\" name=\"subject\" id=\"subject\" size=\"50\" value=\"" . htmlentities(stripslashes($subject), ENT_QUOTES) . "\" />\n";
	echo "<br />\n";
	echo "External Reference ID: <input type=\"text\" name=\"reference_id\" id=\"reference_id\" size=\"20\" value=\"" . htmlentities($reference_id, ENT_QUOTES) . "\" />\n";
	echo "<br />\n";
	echo "Site/Location: \n";
	create_dropdown("location", $location);
	echo "<br />\n";
	echo "Category: \n";
        create_dropdown("category", $category);
	echo "<br />\n";
	echo "Team: \n";
        create_dropdown("team", $team);
	echo "<br />\n";
	echo "Technology: \n";
        create_dropdown("technology", $technology);
	echo "<br />\n";
	echo "Owner: \n";
        create_dropdown("user", $owner, "owner");
	echo "<br />\n";
	echo "Owner&#39;s Manager: \n";
        create_dropdown("user", $manager, "manager");
	echo "<br />\n";
        // If this is CLASSIC risk scoring
        if ($scoring_method == 1)
        {
        	echo "Current Likelihood: \n";
        	create_dropdown("likelihood", $CLASSIC_likelihood, NULL, false);
        	echo "<br />\n";
        	echo "Current Impact: \n";
        	create_dropdown("impact", $CLASSIC_impact, NULL, false);
        	echo "<br />\n";
	}
        // If this is CVSS risk scoring
        else if ($scoring_method == "2")
        {
                echo "Attack Vector: \n";
		create_cvss_dropdown("AccessVector", $AccessVector, false);
                echo "<br />\n";
                echo "Attack Complexity: \n";
		create_cvss_dropdown("AccessComplexity", $AccessComplexity, false);
                echo "<br />\n";
                echo "Authentication: \n";
		create_cvss_dropdown("Authentication", $Authentication, false);
                echo "<br />\n";
                echo "Confidentiality Impact: \n";
		create_cvss_dropdown("ConfImpact", $ConfImpact, false);
                echo "<br />\n";
                echo "Integrity Impact: \n";
		create_cvss_dropdown("IntegImpact", $IntegImpact, false);
                echo "<br />\n";
                echo "Availability Impact: \n";
		create_cvss_dropdown("AvailImpact", $AvailImpact, false);
                echo "<br />\n";
                echo "Exploitability: \n";
		create_cvss_dropdown("Exploitability", $Exploitability, false);
                echo "<br />\n";
                echo "Remediation Level: \n";
		create_cvss_dropdown("RemediationLevel", $RemediationLevel, false);
                echo "<br />\n";
                echo "Report Confidence: \n";
		create_cvss_dropdown("ReportConfidence", $ReportConfidence, false);
                echo "<br />\n";
                echo "Collateral Damage Potential: \n";
		create_cvss_dropdown("CollateralDamagePotential", $CollateralDamagePotential, false);
                echo "<br />\n";
                echo "Target Distribution: \n";
		create_cvss_dropdown("TargetDistribution", $TargetDistribution, false);
                echo "<br />\n";
                echo "Confidentiality Requirement: \n";
		create_cvss_dropdown("ConfidentialityRequirement", $ConfidentialityRequirement, false);
                echo "<br />\n";
                echo "Integrity Requirement: \n";
		create_cvss_dropdown("IntegrityRequirement", $IntegrityRequirement, false);
                echo "<br />\n";
                echo "Availability Requirement: \n";
		create_cvss_dropdown("AvailabilityRequirement", $AvailabilityRequirement, false);
                echo "<br />\n";
        }

        echo "<label>Risk Assessment</label>\n";
        echo "<textarea name=\"assessment\" cols=\"50\" rows=\"3\" id=\"assessment\">" . htmlentities(stripslashes($assessment), ENT_QUOTES) . "</textarea>\n";
        echo "<label>Additional Notes</label>\n";
        echo "<textarea name=\"notes\" cols=\"50\" rows=\"3\" id=\"notes\">" . htmlentities(stripslashes($notes), ENT_QUOTES) . "</textarea>\n";
        echo "<div class=\"form-actions\">\n";
        echo "<button type=\"submit\" name=\"update_details\" class=\"btn btn-primary\">Update</button>\n";
        echo "</div>\n";
}
// Otherwise we are just viewing the risk
else
{
        echo "Submission Date: \n";
        echo "<input type=\"text\" name=\"submission_date\" id=\"submission_date\" size=\"50\" value=\"" . $submission_date . "\" disabled=\"disabled\" />\n";
        echo "<br />\n";
        echo "Subject: \n";
        echo "<input type=\"text\" name=\"subject\" id=\"subject\" size=\"50\" value=\"" . htmlentities(stripslashes($subject), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
	echo "<br />\n";
        echo "External Reference ID: \n";
	echo " <input type=\"text\" name=\"reference_id\" id=\"reference_id\" size=\"20\" value=\"" . htmlentities($reference_id, ENT_QUOTES) . "\" disabled=\"disabled\" />\n
";
        echo "<br />\n";
        echo "Site/Location: \n";
        echo "<input type=\"text\" name=\"location\" id=\"location\" size=\"50\" value=\"" . htmlentities(get_name_by_value("location", $location), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
        echo "<br />\n";
	echo "Category: \n";
        echo "<input type=\"text\" name=\"category\" id=\"category\" size=\"50\" value=\"" . htmlentities(get_name_by_value("category", $category), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
	echo "<br />\n";
	echo "Team: \n";
        echo "<input type=\"text\" name=\"team\" id=\"team\" size=\"50\" value=\"" . htmlentities(get_name_by_value("team", $team), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
	echo "<br />\n";
	echo "Technology: \n";
        echo "<input type=\"text\" name=\"technology\" id=\"technology\" size=\"50\" value=\"" . htmlentities(get_name_by_value("technology", $technology), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
	echo "<br />\n";
	echo "Owner: \n";
        echo "<input type=\"text\" name=\"owner\" id=\"owner\" size=\"50\" value=\"" . htmlentities(get_name_by_value("user", $owner), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
	echo "<br />\n";
	echo "Owner&#39;s Manager: \n";
        echo "<input type=\"text\" name=\"manager\" id=\"manager\" size=\"50\" value=\"" . htmlentities(get_name_by_value("user", $manager), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
	echo "<br />\n";

	// If this is CLASSIC risk scoring
	if ($scoring_method == 1)
	{
        	echo "Current Likelihood: \n";
        	echo "<input type=\"text\" name=\"likelihood\" id=\"likelihood\" size=\"50\" value=\"" . htmlentities(get_name_by_value("likelihood", $CLASSIC_likelihood), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
        	echo "<br />\n";
        	echo "Current Impact: \n";
        	echo "<input type=\"text\" name=\"impact\" id=\"impact\" size=\"50\" value=\"" . htmlentities(get_name_by_value("impact", $CLASSIC_impact), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
        	echo "<br />\n";
	}
	// If this is CVSS risk scoring
	else if ($scoring_method == "2")
	{
		echo "Attack Vector: \n";
		echo "<input type=\"text\" name=\"AccessVector\" id=\"AccessVector\" size=\"50\" value=\"" . htmlentities(stripslashes(get_cvss_name("AccessVector", $AccessVector)), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Attack Complexity: \n";
                echo "<input type=\"text\" name=\"AccessComplexity\" id=\"AccessComplexity\" size=\"50\" value=\"" . htmlentities(stripslashes(get_cvss_name("AccessComplexity", $AccessComplexity)), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Authentication: \n";
                echo "<input type=\"text\" name=\"Authentication\" id=\"Authentication\" size=\"50\" value=\"" . htmlentities(stripslashes(get_cvss_name("Authentication", $Authentication)), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Confidentiality Impact: \n";
                echo "<input type=\"text\" name=\"ConfImpact\" id=\"ConfImpact\" size=\"50\" value=\"" . htmlentities(stripslashes(get_cvss_name("ConfImpact", $ConfImpact)), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Integrity Impact: \n";
                echo "<input type=\"text\" name=\"IntegImpact\" id=\"IntegImpact\" size=\"50\" value=\"" . htmlentities(stripslashes(get_cvss_name("IntegImpact", $IntegImpact)), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Availability Impact: \n";
                echo "<input type=\"text\" name=\"AvailImpact\" id=\"AvailImpact\" size=\"50\" value=\"" . htmlentities(stripslashes(get_cvss_name("AvailImpact", $AvailImpact)), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Exploitability: \n";
                echo "<input type=\"text\" name=\"Exploitability\" id=\"Exploitability\" size=\"50\" value=\"" . htmlentities(stripslashes(get_cvss_name("Exploitability", $Exploitability)), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Remediation Level: \n";
                echo "<input type=\"text\" name=\"RemediationLevel\" id=\"RemediationLevel\" size=\"50\" value=\"" . htmlentities(stripslashes(get_cvss_name("RemediationLevel", $RemediationLevel)), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Report Confidence: \n";
                echo "<input type=\"text\" name=\"ReportConfidence\" id=\"ReportConfidence\" size=\"50\" value=\"" . htmlentities(stripslashes(get_cvss_name("ReportConfidence", $ReportConfidence)), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Collateral Damage Potential: \n";
                echo "<input type=\"text\" name=\"CollateralDamagePotential\" id=\"CollateralDamagePotential\" size=\"50\" value=\"" . htmlentities(stripslashes(get_cvss_name("CollateralDamagePotential", $CollateralDamagePotential)), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Target Distribution: \n";
                echo "<input type=\"text\" name=\"TargetDistribution\" id=\"TargetDistribution\" size=\"50\" value=\"" . htmlentities(stripslashes(get_cvss_name("TargetDistribution", $TargetDistribution)), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Confidentiality Requirement: \n";
                echo "<input type=\"text\" name=\"ConfidentialityRequirement\" id=\"ConfidentialityRequirement\" size=\"50\" value=\"" . htmlentities(stripslashes(get_cvss_name("ConfidentialityRequirement", $ConfidentialityRequirement)), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Integrity Requirement: \n";
                echo "<input type=\"text\" name=\"IntegrityRequirement\" id=\"IntegrityRequirement\" size=\"50\" value=\"" . htmlentities(stripslashes(get_cvss_name("IntegrityRequirement", $IntegrityRequirement)), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Availability Requirement: \n";
                echo "<input type=\"text\" name=\"AvailabilityRequirement\" id=\"AvailabilityRequirement\" size=\"50\" value=\"" . htmlentities(stripslashes(get_cvss_name("AvailabilityRequirement", $AvailabilityRequirement)), ENT_QUOTES) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
	}

        echo "<label>Risk Assessment</label>\n";
        echo "<textarea name=\"assessment\" cols=\"50\" rows=\"3\" id=\"assessment\" disabled=\"disabled\">" . htmlentities(stripslashes($assessment), ENT_QUOTES) . "</textarea>\n";
        echo "<label>Additional Notes</label>\n";
        echo "<textarea name=\"notes\" cols=\"50\" rows=\"3\" id=\"notes\" disabled=\"disabled\">" . htmlentities(stripslashes($notes), ENT_QUOTES) . "</textarea>\n";
        echo "<div class=\"form-actions\">\n";
	echo "<button type=\"submit\" name=\"edit_details\" class=\"btn btn-primary\">Edit Details</button>\n";
        echo "</div>\n";
}
?>
              </div>
            </div>
            <div class="span4">
              <div class="well">
                <h4>Mitigation</h4>
<?php
// If the user has selected to edit the mitigation
if (isset($_POST['edit_mitigation']))
{ 
        echo "Mitigation Date: \n";
        echo "<input type=\"text\" name=\"mitigation_date\" id=\"mitigation_date\" size=\"50\" value=\"" . $mitigation_date . "\" disabled=\"disabled\" />\n";
        echo "<br />\n";
        echo "Planning Strategy: \n";
	create_dropdown("planning_strategy", $planning_strategy);
	echo "<br />\n";
        echo "Mitigation Effort: \n";
        create_dropdown("mitigation_effort", $mitigation_effort);
        echo "<br />\n";
        echo "<label>Current Solution</label>\n";
        echo "<textarea name=\"current_solution\" cols=\"50\" rows=\"3\" id=\"current_solution\">" . htmlentities(stripslashes($current_solution), ENT_QUOTES) . "</textarea>\n";
        echo "<label>Security Requirements</label>\n";
        echo "<textarea name=\"security_requirements\" cols=\"50\" rows=\"3\" id=\"security_requirements\">" . htmlentities(stripslashes($security_requirements), ENT_QUOTES) . "</textarea>\n";
        echo "<label>Security Recommendations</label>\n";
        echo "<textarea name=\"security_recommendations\" cols=\"50\" rows=\"3\" id=\"security_recommendations\">" . htmlentities(stripslashes($security_recommendations), ENT_QUOTES) . "</textarea>\n";
        echo "<div class=\"form-actions\">\n";
        echo "<button type=\"submit\" name=\"update_mitigation\" class=\"btn btn-primary\">Update</button>\n";
        echo "</div>\n";
}
// Otherwise we are just viewing the mitigation
else
{
        echo "Mitigation Date: \n";
        echo "<input type=\"text\" name=\"mitigation_date\" id=\"mitigation_date\" size=\"50\" value=\"" . $mitigation_date . "\" disabled=\"disabled\" />\n";
        echo "<br />\n";
        echo "Planning Strategy: \n";
        echo "<input type=\"text\" name=\"planning_strategy\" id=\"planning_strategy\" size=\"50\" value=\"" . get_name_by_value("planning_strategy", $planning_strategy) . "\" disabled=\"disabled\" />\n";
        echo "<br />\n";
        echo "Mitigation Effort: \n";
        echo "<input type=\"text\" name=\"mitigation_effort\" id=\"mitigation_effort\" size=\"50\" value=\"" . get_name_by_value("mitigation_effort", $mitigation_effort) . "\" disabled=\"disabled\" />\n";
        echo "<br />\n";
	echo "<label>Current Solution</label>\n";
        echo "<textarea name=\"current_solution\" cols=\"50\" rows=\"3\" id=\"current_solution\" disabled=\"disabled\">" . htmlentities(stripslashes($current_solution), ENT_QUOTES) . "</textarea>\n";
	echo "<label>Security Requirements</label>\n";
        echo "<textarea name=\"security_requirements\" cols=\"50\" rows=\"3\" id=\"security_requirements\" disabled=\"disabled\">" . htmlentities(stripslashes($security_requirements), ENT_QUOTES) . "</textarea>\n";
	echo "<label>Security Recommendations</label>\n";
        echo "<textarea name=\"security_recommendations\" cols=\"50\" rows=\"3\" id=\"security_recommendations\" disabled=\"disabled\">" . htmlentities(stripslashes($security_recommendations), ENT_QUOTES) . "</textarea>\n";
        echo "<div class=\"form-actions\">\n";
        echo "<button type=\"submit\" name=\"edit_mitigation\" class=\"btn btn-primary\">Edit Mitigation</button>\n";
        echo "</div>\n";
}
?>
              </div>
            </div>
            <div class="span4">
              <div class="well">
                <h4>Last Review</h4>
<?php
        echo "Review Date: \n";
        echo "<input type=\"text\" name=\"review_date\" id=\"review_date\" size=\"50\" value=\"" . $review_date . "\" disabled=\"disabled\" />\n";
        echo "<br />\n";
        echo "Reviewer: \n";
        echo "<input type=\"text\" name=\"reviewer\" id=\"reviewer\" size=\"50\" value=\"" . get_name_by_value("user", $reviewer) . "\" disabled=\"disabled\" />\n";
        echo "<br />\n";
        echo "Review: \n";
        echo "<input type=\"text\" name=\"review\" id=\"review\" size=\"50\" value=\"" . get_name_by_value("review", $review) . "\" disabled=\"disabled\" />\n";
	echo "<br />\n";
        echo "Next Step: \n";
	echo "<input type=\"text\" name=\"next_step\" id=\"next_step\" size=\"50\" value=\"" . get_name_by_value("next_step", $next_step) . "\" disabled=\"disabled\" />\n";
        echo "<br />\n";
        echo "<label>Comments</label>\n";
        echo "<textarea name=\"comments\" cols=\"50\" rows=\"3\" id=\"comments\" disabled=\"disabled\">" . htmlentities(stripslashes($comments), ENT_QUOTES) . "</textarea>\n";
	echo "<p><a href=\"reviews.php?id=".$id."\">View All Reviews</a></p>";
?>
              </div>
            </div>
            </form>
          </div>
          <div class="row-fluid">
            <div class="well">
              <h4>Comments</h4>
              <?php get_comments($id); ?>
            </div>
          </div>
          <div class="row-fluid">
            <div class="well">
              <h4>Audit Trail</h4>
              <?php get_audit_trail($id); ?>
            </div>
          </div>
        </div>
      </div>
    </div>
  </body>

</html>
