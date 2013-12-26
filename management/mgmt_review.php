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

	// Default is not approved
	$approved = false;

        // Check if access is authorized
        if (!isset($_SESSION["access"]) || $_SESSION["access"] != "granted")
        {
                header("Location: ../index.php");
                exit(0);
        }

        // Check if a risk ID was sent
        if (isset($_GET['id']) || isset($_POST['id']))
        {
                if (isset($_GET['id']))
                {
                        $id = htmlentities($_GET['id'], ENT_QUOTES);
                }
                else if (isset($_POST['id']))
                {
                        $id = htmlentities($_POST['id'], ENT_QUOTES);
                }

                // If team separation is enabled
                if (team_separation_extra())
                {
                        // Include the team separation extra
			require_once($_SERVER{'DOCUMENT_ROOT'} . "/extras/team_separation.php");

                        // If the user does not have access to the risk
                        if (!grant_access($_SESSION['uid'], $id))
                        {
                                // Redirect back to the page the workflow started on
                                header("Location: " . $_SESSION["workflow_start"]);
                                exit(0);
                        }
                }

                // Get the details of the risk
                $risk = get_risk_by_id($id);

                $status = htmlentities($risk[0]['status'], ENT_QUOTES);
                $subject = htmlentities(stripslashes($risk[0]['subject']), ENT_QUOTES);
                $reference_id = htmlentities(stripslashes($risk[0]['reference_id']), ENT_QUOTES);
                $location = htmlentities($risk[0]['location'], ENT_QUOTES);
                $category = htmlentities($risk[0]['category'], ENT_QUOTES);
                $team = htmlentities($risk[0]['team'], ENT_QUOTES);
                $technology = htmlentities($risk[0]['technology'], ENT_QUOTES);
                $owner = htmlentities($risk[0]['owner'], ENT_QUOTES);
                $manager = htmlentities($risk[0]['manager'], ENT_QUOTES);
                $assessment = htmlentities($risk[0]['assessment'], ENT_QUOTES);
                $notes = htmlentities($risk[0]['notes'], ENT_QUOTES);
                $submission_date = htmlentities($risk[0]['submission_date'], ENT_QUOTES);
                $mitigation_id = htmlentities($risk[0]['mitigation_id'], ENT_QUOTES);
                $mgmt_review = htmlentities($risk[0]['mgmt_review'], ENT_QUOTES);
                $calculated_risk = $risk[0]['calculated_risk'];
		$risk_level = get_risk_level_name($calculated_risk);

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
                        $mitigation_date = "";
                        $planning_strategy = "";
                        $mitigation_effort = "";
                        $current_solution = "";
                        $security_requirements = "";
                        $mitigation_date = "N/A";
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

		// If the risk level is high and they have permission
		if (($risk_level == "High") && ($_SESSION['review_high'] == 1))
		{
			// Review is approved
			$approved = true;
		}
		// If the risk level is medium and they have permission
		else if (($risk_level == "Medium") && ($_SESSION['review_medium'] == 1))
		{
                        // Review is approved
                        $approved = true;
		}
		// If the risk level is low and they have permission
		else if (($risk_level == "Low") && ($_SESSION['review_low'] == 1))
		{
                        // Review is approved
                        $approved = true;
		}
        }

	// If they are not approved to review the risk
	if (!($approved))
	{
		// There is an alert
		$alert = true;
		$alert_message = "You do not have permission to review " . $risk_level . " level risks.  Any reviews that you attempt to submit will not be recorded.  Please contact an administrator if you feel that you have reached this message in error.";
	}

        // Check if a new risk mitigation was submitted
        if (isset($_POST['submit']))
        {
		// If they are approved to review the risk
		if ($approved)
		{
                	$status = "Mgmt Reviewed";
                	$review = (int)addslashes($_POST['review']);
			$next_step = (int)addslashes($_POST['next_step']);
                	$reviewer = $_SESSION['uid'];
                	$comments = addslashes($_POST['comments']);

                	// Submit review
                	submit_management_review($id, $status, $review, $next_step, $reviewer, $comments);

                	// Audit log
                	$risk_id = $id;
                	$message = "A management review was submitted for risk ID \"" . $risk_id . "\" by username \"" . $_SESSION['user'] . "\".";
                	write_log($risk_id, $_SESSION['uid'], $message);

			// If the reviewer rejected the risk
			if ($review == 2)
			{
                		$status = "Closed";
                		$close_reason = "The risk was rejected by the reviewer.";
                		$note = "Risk was closed automatically when the reviewer rejected the risk.";

                		// Close the risk
                		close_risk($risk_id, $_SESSION['uid'], $status, $close_reason, $note);

                		// Audit log
                		$message = "Risk ID \"" . $risk_id . "\" automatically closed when username \"" . $_SESSION['user'] . "\" rejected the risk.";
                		write_log($risk_id, $_SESSION['uid'], $message);
			}

                        // Redirect back to the page the workflow started on
                        header("Location: " . $_SESSION["workflow_start"] . "?reviewed=true");
		}
		// They do not have permissions to review the risk
		else
		{
                	// There is an alert
                	$alert = true;
                	$alert_message = "You do not have permission to review " . $risk_level . " level risks.  The review that you attempted to submit was not recorded.  Please contact an administrator if you feel that you have reached this message in error.";
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
  </head>
  
  <body>
    <?php if ($alert) echo "<script>alert(\"" . $alert_message . "\");</script>"; ?>
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
            <li class="active">
              <a href="management_review.php">III. Perform Management Reviews</a> 
            </li>
            <li>
              <a href="prioritize_planning.php">IV. Prioritize for Project Planning</a> 
            </li>
            <li>
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
                  <li><a href="view.php?id=<?php echo $id; ?>">Edit Risk</a></li>
                  <li><a href="comment.php?id=<?php echo $id; ?>">Add a Comment</a></li>
                </ul>
              </div>
              <form name="submit_management_review" method="post" action="">
                <h4><u>Submit Management Review</u></h4>
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
                Review: <?php create_dropdown("review"); ?><br />
	        Next Step: <?php create_dropdown("next_step"); ?><br />
                <label>Comments</label>
                <textarea name="comments" cols="50" rows="3" id="comments"></textarea>
                <div class="form-actions">
                  <button type="submit" name="submit" class="btn btn-primary">Submit</button>
                  <input class="btn" value="Reset" type="reset">
                </div>
              </form>
            </div>
          </div>
          <div class="row-fluid">
            <div class="span6">
              <div class="well">
                <h4>Details</h4>
                Submission Date: <input type="text" name="submission_date" id="submission_date" size="50" value="<?php echo $submission_date ?>" disabled="disabled" /><br />
                Subject: <input type="text" name="subject" id="subject" size="50" value="<?php echo htmlentities($subject, ENT_QUOTES) ?>" disabled="disabled" /><br />
                External Reference ID: <input type="text" name="reference_id" id="reference_id" size="20" value="<?php echo htmlentities($reference_id, ENT_QUOTES) ?>" disabled="disabled" /><br />
                Site/Location: <input type="text" name="location" id="location" size="50" value="<?php echo get_name_by_value("location", $location) ?>" disabled="disabled" /><br />
                Category: <input type="text" name="category" id="category" size="50" value="<?php echo get_name_by_value("category", $category) ?>" disabled="disabled" /><br />
                Team: <input type="text" name="team" id="team" size="50" value="<?php echo get_name_by_value("team", $team) ?>" disabled="disabled" /><br />
                Technology: <input type="text" name="technology" id="technology" size="50" value="<?php echo get_name_by_value("technology", $technology) ?>" disabled="disabled" /><br />
                Owner: <input type="text" name="owner" id="owner" size="50" value="<?php echo get_name_by_value("user", $owner) ?>" disabled="disabled" /><br />
                Owner&#39;s Manager: <input type="text" name="manager" id="manager" size="50" value="<?php echo get_name_by_value("user", $manager) ?>" disabled="disabled" /><br />
<?php
        // If this is CLASSIC risk scoring
        if ($scoring_method == 1)
        {
                echo "Current Likelihood: \n";
                echo "<input type=\"text\" name=\"likelihood\" id=\"likelihood\" size=\"50\" value=\"" . get_name_by_value("likelihood", $CLASSIC_likelihood) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Current Impact: \n";
                echo "<input type=\"text\" name=\"impact\" id=\"impact\" size=\"50\" value=\"" . get_name_by_value("impact", $CLASSIC_impact) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
        }
        // If this is CVSS risk scoring
        else if ($scoring_method == "2")
        {
                echo "Attack Vector: \n";
                echo "<input type=\"text\" name=\"AccessVectorVar\" id=\"AccessVectorVar\" size=\"50\" value=\"" . get_cvss_name("AccessVector", $AccessVector) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Attack Complexity: \n";
                echo "<input type=\"text\" name=\"AccessComplexityVar\" id=\"AccessComplexityVar\" size=\"50\" value=\"" . get_cvss_name("AccessComplexity", $AccessComplexity) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Authentication: \n";
                echo "<input type=\"text\" name=\"AuthenticationVar\" id=\"AuthenticationVar\" size=\"50\" value=\"" . get_cvss_name("Authentication", $Authentication) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Confidentiality Impact: \n";
                echo "<input type=\"text\" name=\"ConfImpactVar\" id=\"ConfImpactVar\" size=\"50\" value=\"" . get_cvss_name("ConfImpact", $ConfImpact) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Integrity Impact: \n";
                echo "<input type=\"text\" name=\"IntegImpactVar\" id=\"IntegImpactVar\" size=\"50\" value=\"" . get_cvss_name("IntegImpact", $IntegImpact) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Availability Impact: \n";
                echo "<input type=\"text\" name=\"AvailImpactVar\" id=\"AvailImpactVar\" size=\"50\" value=\"" . get_cvss_name("AvailImpact", $AvailImpact) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Exploitability: \n";
                echo "<input type=\"text\" name=\"ExploitabilityVar\" id=\"ExploitabilityVar\" size=\"50\" value=\"" . get_cvss_name("Exploitability", $Exploitability) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Remediation Level: \n";
                echo "<input type=\"text\" name=\"RemediationLevelVar\" id=\"RemediationLevelVar\" size=\"50\" value=\"" . get_cvss_name("RemediationLevel", $RemediationLevel) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Report Confidence: \n";
                echo "<input type=\"text\" name=\"ReportConfidenceVar\" id=\"ReportConfidenceVar\" size=\"50\" value=\"" . get_cvss_name("ReportConfidence", $ReportConfidence) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Collateral Damage Potential: \n";
                echo "<input type=\"text\" name=\"CollateralDamagePotentialVar\" id=\"CollateralDamagePotentialVar\" size=\"50\" value=\"" . get_cvss_name("CollateralDamagePotential", $CollateralDamagePotential) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Target Distribution: \n";
                echo "<input type=\"text\" name=\"TargetDistributionVar\" id=\"TargetDistributionVar\" size=\"50\" value=\"" . get_cvss_name("TargetDistribution", $TargetDistribution) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Confidentiality Requirement: \n";
                echo "<input type=\"text\" name=\"ConfidentialityRequirementVar\" id=\"ConfidentialityRequirementVar\" size=\"50\" value=\"" . get_cvss_name("ConfidentialityRequirement", $ConfidentialityRequirement) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Integrity Requirement: \n";
                echo "<input type=\"text\" name=\"IntegrityRequirementVar\" id=\"IntegrityRequirementVar\" size=\"50\" value=\"" . get_cvss_name("IntegrityRequirement", $IntegrityRequirement) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
                echo "Availability Requirement: \n";
                echo "<input type=\"text\" name=\"AvailabilityRequirementVar\" id=\"AvailabilityRequirementVar\" size=\"50\" value=\"" . get_cvss_name("AvailabilityRequirement", $AvailabilityRequirement) . "\" disabled=\"disabled\" />\n";
                echo "<br />\n";
        }
?>
                <label>Risk Assessment</label>
                <textarea name="assessment" cols="50" rows="3" id="assessment" disabled="disabled"><?php echo htmlentities(stripslashes($assessment), ENT_QUOTES) ?></textarea>
                <label>Additional Notes</label>
                <textarea name="notes" cols="50" rows="3" id="notes" disabled="disabled"><?php echo htmlentities(stripslashes($notes), ENT_QUOTES) ?></textarea>
              </div>
            </div>
            <div class="span6">
              <div class="well">
                <h4>Mitigation</h4>
                Mitigation Date: <input type="text" name="mitigation_date" id="mitigation_date" size="50" value="<?php echo $mitigation_date ?>" disabled="disabled" /><br />
                Planning Strategy: <input type="text" name="planning_strategy" id="planning_strategy" size="50" value="<?php echo get_name_by_value("planning_strategy", $planning_strategy) ?>" disabled="disabled" /><br />
                Mitigation Effort: <input type="text" name="mitigation_effort" id="mitigation_effort" size="50" value="<?php echo get_name_by_value("mitigation_effort", $mitigation_effort) ?>" disabled="disabled" /><br />
                <label>Current Solution</label>
                <textarea name="current_solution" cols="50" rows="3" id="current_solution" disabled="disabled"><?php echo htmlentities(stripslashes($current_solution), ENT_QUOTES) ?></textarea>
                <label>Security Requirements</label>
                <textarea name="security_requirements" cols="50" rows="3" id="security_requirements" disabled="disabled"><?php echo htmlentities(stripslashes($security_requirements), ENT_QUOTES) ?></textarea>
                <label>Security Recommendations</label>
                <textarea name="security_recommendations" cols="50" rows="3" id="security_recommendations" disabled="disabled"><?php echo htmlentities(stripslashes($security_recommendations), ENT_QUOTES) ?></textarea>
              </div>
            </div>
          </div>
          <div class="row-fluid">
            <div class="well">
              <h4>Comments</h4>
              <?php get_comments($id); ?>
            </div>
          </div>
        </div>
      </div>
    </div>
  </body>

</html>
