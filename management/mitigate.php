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

	// Check if the user has access to plan mitigations
	if (!isset($_SESSION["plan_mitigations"]) || $_SESSION["plan_mitigations"] != 1)
	{
		$plan_mitigations = false;
		$alert = true;
		$alert_message = "You do not have permission to plan mitigations.  Any mitigations that you attempt to submit will not be recorded.  Please contact an Administrator if you feel that you have reached this message in error.";
	}
	else $plan_mitigations = true;

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

        // Check if a new risk mitigation was submitted and the user has permissions to plan mitigations
        if ((isset($_POST['submit'])) && $plan_mitigations)
        {
                $status = "Mitigation Planned";
                $planning_strategy = (int)addslashes($_POST['planning_strategy']);
		$mitigation_effort = (int)addslashes($_POST['mitigation_effort']);
                $current_solution = addslashes($_POST['current_solution']);
                $security_requirements = addslashes($_POST['security_requirements']);
                $security_recommendations = addslashes($_POST['security_recommendations']);

                // Submit mitigation
                submit_mitigation($id, $status, $planning_strategy, $mitigation_effort, $current_solution, $security_requirements, $security_recommendations);

                // Audit log
                $risk_id = $id;
                $message = "A mitigation was submitted for risk ID \"" . $risk_id . "\" by username \"" . $_SESSION['user'] . "\".";
                write_log($risk_id, $_SESSION['uid'], $message);

                // Redirect back to the page the workflow started on
                header("Location: " . $_SESSION["workflow_start"] . "?mitigated=true");
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
            <li class="active">
              <a href="plan_mitigations.php">II. Plan Your Mitigations</a> 
            </li>
            <li>
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
                ?>
                  <li><a href="view.php?id=<?php echo $id; ?>">Edit Risk</a></li>
                  <li><a href="mgmt_review.php?id=<?php echo $id; ?>">Perform a Review</a></li>
                  <li><a href="comment.php?id=<?php echo $id; ?>">Add a Comment</a></li>
                </ul>
              </div>
              <form name="submit_mitigation" method="post" action="">
                <h4><u>Submit Risk Mitigation</u></h4>
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

                Planning Strategy: <?php create_dropdown("planning_strategy"); ?><br />
		Mitigation Effort: <?php create_dropdown("mitigation_effort"); ?><br />
                <label>Current Solution</label>
                <textarea name="current_solution" cols="50" rows="3" id="current_solution"></textarea>
                <label>Security Requirements</label>
                <textarea name="security_requirements" cols="50" rows="3" id="security_requirements"></textarea>
                <label>Security Recommendations</label>
                <textarea name="security_recommendations" cols="50" rows="3" id="security_recommendations"></textarea>
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
                <h4>Last Review</h4>
                Review Date: <input type="text" name="review_date" id="review_date" size="50" value="<?php echo $review_date ?>" disabled="disabled" /><br />
                Reviewer: <input type="text" name="reviewer" id="reviewer" size="50" value="<?php echo get_name_by_value("user", $reviewer) ?>" disabled="disabled" /><br />
                Review: <input type="text" name="review" id="review" size="50" value="<?php echo get_name_by_value("review", $review) ?>" disabled="disabled" /><br />
                Next Step: <input type="text" name="next_step" id="next_step" size="50" value="<?php echo get_name_by_value("next_step", $next_step) ?>" disabled="disabled" /><br />
                <label>Comments</label>
                <textarea name="comments" cols="50" rows="3" id="comments" disabled="disabled"><?php echo  htmlentities($comments, ENT_QUOTES) ?></textarea>
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
