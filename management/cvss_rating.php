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

        // Check if access is authorized
        if (!isset($_SESSION["access"]) || $_SESSION["access"] != "granted")
        {
                header("Location: ../index.php");
                exit(0);
        }
?>

<html>
<head>
<title></title>
<link rel="stylesheet" type="text/css" href="../css/style.css">
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1">
<link href="../css/front-style.css" rel="stylesheet" type="text/css">
<script language="javascript" src="../js/basescript.js" type="text/javascript"></script>
<script type="text/javascript" language="JavaScript">
  <!--
  var parent_window = window.opener;

  function cvssSubmit() {
    if (parent_window && !parent_window.closed) {
      parent_window.document.getElementById('AccessVector').value=this.document.getElementById('AccessVector').value;
      parent_window.document.getElementById('AccessComplexity').value=this.document.getElementById('AccessComplexity').value;
      parent_window.document.getElementById('Authentication').value=this.document.getElementById('Authentication').value;
      parent_window.document.getElementById('ConfImpact').value=this.document.getElementById('ConfImpact').value;
      parent_window.document.getElementById('IntegImpact').value=this.document.getElementById('IntegImpact').value;
      parent_window.document.getElementById('AvailImpact').value=this.document.getElementById('AvailImpact').value;
      parent_window.document.getElementById('Exploitability').value=this.document.getElementById('Exploitability').value;
      parent_window.document.getElementById('RemediationLevel').value=this.document.getElementById('RemediationLevel').value;
      parent_window.document.getElementById('ReportConfidence').value=this.document.getElementById('ReportConfidence').value;
      parent_window.document.getElementById('CollateralDamagePotential').value=this.document.getElementById('CollateralDamagePotential').value;
      parent_window.document.getElementById('TargetDistribution').value=this.document.getElementById('TargetDistribution').value;
      parent_window.document.getElementById('ConfidentialityRequirement').value=this.document.getElementById('ConfidentialityRequirement').value;
      parent_window.document.getElementById('IntegrityRequirement').value=this.document.getElementById('IntegrityRequirement').value;
      parent_window.document.getElementById('AvailabilityRequirement').value=this.document.getElementById('AvailabilityRequirement').value;
    }
  }

  function closeWindow() {
    window.opener.closepopup();
  }

  function submitandclose() {
    cvssSubmit();
    closeWindow();
  }

  // -->
</script>
</head>

<body topmargin="0" bottommargin="4" leftmargin="0" rightmargin="0" ><form name="frmCalc" method="post" action="" >
          
<table width="672" border="0" cellpadding="1" cellspacing="0">
	
  <tr>
    <td align="left" valign="top"  bgcolor="#6B7782" >
      <table width="100%" border="0" cellpadding="0" cellspacing="0" bgcolor="#FFFFFF">
      	<tr>
	  <td align="center" background="../images/cal-bg-head.jpg" height="35"><span class="heading">FixRisk CVSS V2.0 Calculator</span></td>
    </tr>
    
    
    <tr>
	  <td align="left"  height="8"></td>
	  </tr>
    
    
	<tr>
    	<td align="left" style="padding-left:10px; padding-right:10px" height="35">This page provides a calculator for creating <A href="http://www.first.org/cvss/" target="_blank">CVSS</A> vulnerability severity scores.  The scores are computed in sequence such that the Base Score is used to calculate the Temporal Score and the Temporal Score is used to calculate the Environmental Score.</td>
    </tr>
	<tr>
	  <td align="left"  height="8"></td>
	  </tr>
        <tr>
          <td><table border="0" cellspacing="0" cellpadding="0">
            <tr>
              <td valign="top">
              <table width="336" border="0" align="right" cellpadding="0" cellspacing="0">

                  <tr bordercolor="#CCCCCC">
                    <td background="../images/cal-bg.jpg"><span class="style2" style="background-repeat:no-repeat">&nbsp;&nbsp;CVSS Score</span></td>
                  </tr>
                  <tr>
                    <td  style="padding-left:5px; padding-right:5px;" ><table width="100%" border="0" cellpadding="1" cellspacing="1">
                      <tr>
                        <td >CVSS Base Score
                          <input type="hidden" name="BaseScore" value="0"></td>
                        <td >0</td>
                      </tr>
                      <tr>
                        <td style="padding-left:10px;">Impact&nbsp;Subscore</td>
                        <td >0
                          <input type="hidden" name="Impact" value="0">                        </td>
                      </tr>
                      <tr>
                        <td  style="padding-left:10px;"> Exploitability&nbsp;Subscore</td>
                        <td >0 
                          <input type="hidden" name="Exploitability" value="0">                        </td>
                      </tr>
                      <tr>
                        <td>CVSS&nbsp;Temporal&nbsp;Score</td>
                        <td>0
                          <input type="hidden" name="TemporalScore" value="0">                       </td>
                      </tr>
                      <tr>
                        <td height="20">CVSS&nbsp;Environmental&nbsp;Score</td>
                        <td>0
                          <input type="hidden" name="EnvironmentalScore" value="0">                        </td>
                      </tr>
                      <tr>
                        <td class="style1"><strong>Overall&nbsp;CVSS&nbsp;Score</strong></td>
                        <td>0
                              <input type="hidden" name="OverAllCvssScore" value="0">                       </td>
                      </tr>
                    </table></td>
                  </tr>
                  <tr>
                    <td height="4"></td>
                  </tr>
                  <tr bordercolor="#CCCCCC">
                    <td background="../images/cal-bg.jpg"><span class="style2" style="background-repeat:no-repeat">&nbsp;&nbsp;Help Desk</span></td>
                  </tr>
                  <tr>
                    <td  style="padding-left:5px; padding-right:5px;" >
                     <div id="divHelp" style="width:100%;height:300px;overflow:auto"></div>
                     
                        <div id="AccessVectorHelp"  style="display:none; visibility:hidden">
                        	 
                              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                <tr>
                                  <td class="cal-head">Local </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  A vulnerability exploitable with only local access requires the attacker
                                  to have either physical access to the vulnerable system or a local (shell) account.
                                  Examples of locally exploitable vulnerabilities are peripheral attacks such as
                                  Firewire/USB DMA attacks, and local privilege escalations (e.g., sudo). </td>
                                </tr>
                                <tr>
                                  <td class="cal-head"> Adjacent Network </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  	A vulnerability exploitable with adjacent network access requires the attacker to have access
                                    to either the broadcast or collision domain of the vulnerable software.  Examples of local 
                                    networks include local IP subnet, Bluetooth, IEEE 802.11, and local Ethernet segment.</td>
                                </tr>
                              <tr>
                                  <td class="cal-head"> Network</td>
                                </tr>
                             
                              <tr>
                                  <td class="cal-text" >
                                  	A vulnerability exploitable with network access means the vulnerable software is bound to the network 
                                    stack and the attacker does not require local network access or local access.  Such a vulnerability is
                                     often termed "remotely exploitable".  An example of a network attack is an RPC buffer overflow.</td>
                                </tr>
                           
                              </table>
                        </div>
                        
                        
                        
                        <div id="AccessComplexityHelp" style="display:none; visibility:hidden">
                        	
                            
                             <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                <tr>
                                  <td class="cal-head">High </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  Specialized access conditions exist. For example:<br>
                                In most configurations, the attacking party must already have elevated privileges or spoof 
                                additional systems in addition to the attacking system (e.g., DNS hijacking).
                                 The attack depends on social engineering methods that would be easily detected by knowledgeable 
                                 people. For example, the victim must perform several suspicious or atypical actions.
                                   The vulnerable configuration is seen very rarely in practice.
                                  If a race condition exists, the window is very narrow.
 </td>
                                </tr>
                                <tr>
                                  <td class="cal-head"> Medium</td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  	The access conditions are somewhat specialized; the following are examples:<br>
                                    The attacking party is limited to a group of systems or users at some level of authorization, 
                                    possibly untrusted. Some information must be gathered before a successful attack can be launched.
                                    The affected configuration is non-default, and is not commonly configured (e.g., a vulnerability
                                    present when a server performs user account authentication via a specific scheme, but not 
                                    present for another authentication scheme).
                                    The attack requires a small amount of social engineering that might occasionally fool cautious 
                                    users (e.g., phishing attacks that modify a web browser?s status bar to show a false link, 
                                    having to be on someone?s ?buddy? list before sending an IM exploit).</td>
                                </tr>
                              <tr>
                                  <td class="cal-head"> Low </td>
                                </tr>
                             
                              <tr>
                                  <td class="cal-text" >
                                  	Specialized access conditions or extenuating circumstances do not exist. The following are examples:<br>
                                    The affected product typically requires access to a wide range of systems and users,
                                    possibly anonymous and untrusted (e.g., Internet-facing web or mail server). The affected
                                    configuration is default or ubiquitous. The attack can be performed manually and requires 
                                    little skill or additional information gathering.The ?race condition? is a lazy one 
                                    (i.e., it is technically a race but easily winnable).</td>
                                </tr>
                           
                              </table>
                            
                            
                            
                            
                            
                        </div>
                         <div id="AuthenticationHelp" style="display:none; visibility:hidden">
                      
                            
                               <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                     <tr>
                                      <td class="cal-head">None</td>
                                    </tr>
                                 
                                  <tr>
                                      <td class="cal-text" >
                                        Authentication is not required to exploit the vulnerability.</td>
                                 </tr>
                                 
                                <tr>
                                  <td class="cal-head">Single Instance</td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  	The vulnerability requires an attacker to be logged into the system
                                     (such as at a command line or via a desktop session or web interface).</td>
                                </tr>
                             	<tr>
                                  <td class="cal-head">Multiple Instance</td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  Exploiting the vulnerability requires that the attacker authenticate two or more times, 
                                  even if the same credentials are used each time. An example is an attacker authenticating to
                                   an operating system in addition to providing credentials to access an application hosted on that system.
 								</td>
                                </tr>
                           
                              </table>
                            
                            
                    
                            
                        </div>
                        <div id="ConfImpactHelp"  style="display:none; visibility:hidden">
                        	 
                              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                <tr>
                                  <td class="cal-head">None </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  There is no impact to the confidentiality of the system. </td>
                                </tr>
                                <tr>
                                  <td class="cal-head"> Partial </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  	There is considerable informational disclosure. Access to some system files is possible, 
                                    but the attacker does not have control over what is obtained, or the scope of the loss is 
                                    constrained. An example is a vulnerability that divulges only certain tables in a database.</td>
                                </tr>
                              <tr>
                                  <td class="cal-head">Complete </td>
                                </tr>
                             
                              <tr>
                                  <td class="cal-text" >
                                  	There is total information disclosure, resulting in all system files being revealed. 
                                    The attacker is able to read all of the system's data (memory, files, etc.)</td>
                                </tr>
                           
                              </table>
                        </div>
                        
                        
                      
                     <div id="IntegImpactHelp"  style="display:none; visibility:hidden">
                        	 
                              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                <tr>
                                  <td class="cal-head">None </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                 There is no impact to the integrity of the system. </td>
                                </tr>
                                <tr>
                                  <td class="cal-head"> Partial </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  	Modification of some system files or information is possible, but the attacker does not have 
                                    control over what can be modified, or the scope of what the attacker can affect is limited. 
                                    For example, system or application files may be overwritten or modified, but either the attacker 
                                    has no control over which files are affected or the attacker can modify files within only a limited 
                                    context or scope.</td>
                                </tr>
                              <tr>
                                  <td class="cal-head">Complete </td>
                                </tr>
                             
                              <tr>
                                  <td class="cal-text" >
                                  	There is a total compromise of system integrity. There is a complete loss of system 
                                    protection,resulting in the entire system being compromised. 
                                    The attacker is able to modify any files on the target system.</td>
                                </tr>
                           
                              </table>
                        </div> 
                      
                      
                      <div id="AvailImpactHelp"  style="display:none; visibility:hidden">
                        	 
                              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                <tr>
                                  <td class="cal-head">None </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                There is no impact to the availability of the system. </td>
                                </tr>
                                <tr>
                                  <td class="cal-head"> Partial </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  	There is reduced performance or interruptions in resource availability. An example is a 
                                    network-based flood attack that permits a limited number of successful connections to an 
                                    Internet service.</td>
                                </tr>
                              <tr>
                                  <td class="cal-head">Complete </td>
                                </tr>
                             
                              <tr>
                                  <td class="cal-text" >
                                  	There is a total shutdown of the affected resource. The attacker can render the resource completely 
                                    unavailable.</td>
                                </tr>
                           
                              </table>
                        </div>
                      
                      <div id="CollateralDamagePotentialHelp"  style="display:none; visibility:hidden">
                        	 
                              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                <tr>
                                  <td class="cal-head">None </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                There is no potential for loss of life, physical assets, productivity or revenue. </td>
                                </tr>
                                <tr>
                                  <td class="cal-head"> Low </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  	A successful exploit of this vulnerability may result in slight physical or property damage. 
                                    Or, there may be a slight loss of revenue or productivity to the organization.</td>
                                </tr>
                              <tr>
                                  <td class="cal-head">Low-Medium  </td>
                                </tr>
                             
                              <tr>
                                  <td class="cal-text" >
                                  	A successful exploit of this vulnerability may result in moderate physical or property damage. Or, 
                                    there may be a moderate loss of revenue or productivity to the organization.</td>
                                </tr>
                                <tr>
                                  <td class="cal-head">Medium-High  </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                               A successful exploit of this vulnerability may result in significant physical or property damage or loss. 
                               Or, there may be a significant loss of revenue or productivity. </td>
                                </tr>
                                <tr>
                                  <td class="cal-head">High </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  	A successful exploit of this vulnerability may result in catastrophic physical or property damage
                                     and loss. Or, there may be a catastrophic loss of revenue or productivity.</td>
                                </tr>
                              
                              </table>
                        </div>
                      
                      
                      <div id="TargetDistributionHelp"  style="display:none; visibility:hidden">
                        	 
                              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                <tr>
                                  <td class="cal-head">None </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                No target systems exist, or targets are so highly specialized that they only exist in a laboratory setting. 
                                Effectively 0% of the environment is at risk.</td>
                                </tr>
                                <tr>
                                  <td class="cal-head"> Low </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  	Targets exist inside the environment, but on a small scale. Between 1% - 25% of the total environment is at risk.</td>
                                </tr>
                              <tr>
                                  <td class="cal-head">Medium  </td>
                                </tr>
                             
                              <tr>
                                  <td class="cal-text" >
                                  	Targets exist inside the environment, but on a medium scale. Between 26% - 75% of the total environment is at risk.</td>
                                </tr>
                                <tr>
                                  <td class="cal-head">High  </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                               Targets exist inside the environment on a considerable scale. Between 76% - 100% of the total environment is considered at risk. </td>
                                </tr>
                                
                              </table>
                        </div>
                      
                      <div id="ExploitabilityHelp"  style="display:none; visibility:hidden">
                        	 
                              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                <tr>
                                  <td class="cal-head">Unproven that exploit exists </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                No exploit code is available, or an exploit is entirely theoretical.</td>
                                </tr>
                                <tr>
                                  <td class="cal-head"> Proof of concept code </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  	Proof-of-concept exploit code or an attack demonstration that is not practical for most systems is available.
                                     The code or technique is not functional in all situations 
                                     and may require substantial modification by a skilled attacker.</td>
                                </tr>
                              <tr>
                                  <td class="cal-head">Functional exploit exists </td>
                                </tr>
                             
                              <tr>
                                  <td class="cal-text" >
                                  	Functional exploit code is available. The code works in most situations where the vulnerability exists.</td>
                                </tr>
                                <tr>
                                  <td class="cal-head">Widespread</td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                               Either the vulnerability is exploitable by functional mobile autonomous code, or no exploit is required 
                               (manual trigger) and details are widely available. The code works in every situation, or is actively 
                               being delivered via a mobile autonomous agent (such as a worm or virus). </td>
                                </tr>
                                
                              </table>
                        </div>
                      
                      
                      
                      <div id="RemediationLevelHelp"  style="display:none; visibility:hidden">
                        	 
                              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                <tr>
                                  <td class="cal-head">Official Fix</td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                A complete vendor solution is available. Either the vendor has issued an official patch,
                                 or an upgrade is available.</td>
                                </tr>
                                <tr>
                                  <td class="cal-head"> Temporary Fix  </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  	There is an official but temporary fix available. This includes instances where the 
                                    vendor issues a temporary hotfix, tool, or workaround.</td>
                                </tr>
                                
                                
                                
                               <tr>
                                  <td class="cal-head">Workaround </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  	There is an unofficial, non-vendor solution available. In some cases, users of the affected technology will create a patch of their own or provide steps to work around or otherwise mitigate the vulnerability.</td>
                                </tr>  
                                
                                
                                
                                
                                
                                
                                
                                
                                
                              <tr>
                                  <td class="cal-head">Unavailable </td>
                                </tr>
                             
                              <tr>
                                  <td class="cal-text" >
                                  	There is either no solution available or it is impossible to apply.</td>
                                </tr>
                                                         
                              </table>
                        </div>
                      
                      
                      
                      
                      
                      
                      
                      <div id="ReportConfidenceHelp"  style="display:none; visibility:hidden">
                        	 
                              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                <tr>
                                  <td class="cal-head">Not Confirmed </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                There is a single unconfirmed source or possibly multiple conflicting reports. There is 
                                little confidence in the validity of the reports. An example is a rumor that surfaces from 
                                the hacker underground.</td>
                                </tr>
                                <tr>
                                  <td class="cal-head"> Uncorroborated  </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  	There are multiple non-official sources, possibly including independent security companies or research 
                                    organizations. At this point there may be conflicting technical details or some other lingering ambiguity.</td>
                                </tr>
                              <tr>
                                  <td class="cal-head">Confirmed </td>
                                </tr>
                             
                              <tr>
                                  <td class="cal-text" >
                                  	The vulnerability has been acknowledged by the vendor or author of the affected technology. 
                                    The vulnerability may also be ?Confirmed? when its existence is confirmed from an external event 
                                    such as publication of functional or proof-of-concept exploit code or widespread exploitation.</td>
                                </tr>
                                                        
                              </table>
                        </div>
                      
                      
               <div id="ConfidentialityRequirementHelp"  style="display:none; visibility:hidden">
                        	 
                              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                <tr>
                                  <td class="cal-head">Low </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                Loss of [confidentiality | integrity | availability] is likely to have only a limited adverse effect on 
                                the organization or individuals associated with the organization (e.g., employees, customers).</td>
                                </tr>
                                <tr>
                                  <td class="cal-head"> Medium </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  	Loss of [confidentiality | integrity | availability] is likely to have a serious adverse effect on the organization 
                                    or individuals associated with the organization (e.g., employees, customers).</td>
                                </tr>
                              <tr>
                                  <td class="cal-head">High</td>
                                </tr>
                             
                              <tr>
                                  <td class="cal-text" >
                                  	Loss of [confidentiality | integrity | availability] is likely to have a catastrophic adverse effect on 
                                    the organization or individuals associated with the organization (e.g., employees, customers).</td>
                                </tr>
                                                          
                              </table>
                        </div>       
                      
                      
                      
                     <div id="IntegrityRequirementHelp"  style="display:none; visibility:hidden">
                        	 
                              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                <tr>
                                  <td class="cal-head">Low </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                Loss of [confidentiality | integrity | availability] is likely to have only a limited adverse effect on 
                                the organization or individuals associated with the organization (e.g., employees, customers).</td>
                                </tr>
                                <tr>
                                  <td class="cal-head"> Medium </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  	Loss of [confidentiality | integrity | availability] is likely to have a serious adverse effect on the organization 
                                    or individuals associated with the organization (e.g., employees, customers).</td>
                                </tr>
                              <tr>
                                  <td class="cal-head">High</td>
                                </tr>
                             
                              <tr>
                                  <td class="cal-text" >
                                  	Loss of [confidentiality | integrity | availability] is likely to have a catastrophic adverse effect on 
                                    the organization or individuals associated with the organization (e.g., employees, customers).</td>
                                </tr>
                                                           
                              </table>
                        </div> 
                      
                      <div id="AvailabilityRequirementHelp"  style="display:none; visibility:hidden">
                        	 
                              <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                <tr>
                                  <td class="cal-head">Low </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                Loss of [confidentiality | integrity | availability] is likely to have only a limited adverse effect on 
                                the organization or individuals associated with the organization (e.g., employees, customers).</td>
                                </tr>
                                <tr>
                                  <td class="cal-head"> Medium </td>
                                </tr>
                                <tr>
                                  <td class="cal-text" >
                                  	Loss of [confidentiality | integrity | availability] is likely to have a serious adverse effect on the organization 
                                    or individuals associated with the organization (e.g., employees, customers).</td>
                                </tr>
                              <tr>
                                  <td class="cal-head">High</td>
                                </tr>
                             
                              <tr>
                                  <td class="cal-text" >
                                  	Loss of [confidentiality | integrity | availability] is likely to have a catastrophic adverse effect on 
                                    the organization or individuals associated with the organization (e.g., employees, customers).</td>
                                </tr>
                                                          
                              </table>
                        </div>
                      
                      <script language="javascript">
							
							function showHelp(divId)
							{
								getRef("divHelp").innerHTML=getRef(divId).innerHTML;
															
							}
							function hideHelp()
							{
								getRef("divHelp").innerHTML="";
							}
							
                        </script>
                    </td>
                  </tr>
              </table></td>
              <td background="../images/separetor.jpg" ><img src="../images/separetor.jpg"></td>
              <td valign="top"><table width="100%" border="0" cellspacing="0" cellpadding="0">
                  <tr>
                    <td valign="top"><table width="336" border="0" cellpadding="0" cellspacing="0">
                        <tr bordercolor="#CCCCCC">
                          <td width="329" background="../images/cal-bg.jpg" bgcolor="#E6E2E1" class="style2"  style="background-repeat:no-repeat">&nbsp; Base Score Metrics</td>
                        </tr>
                        <tr>
                          <td style="padding-left:5px;" ><table width="100%"  border="0" cellpadding="1" cellspacing="1" >
                            <tr>
                              <td colspan="2" class="style1">Exploitability Metrics</td>
                            </tr>
                            <tr>
                              <td width="117">Attack Vector</td>
                              <td width="119"><table border="0" cellspacing="0" cellpadding="0">
                                <tr>
                                  <td>
                                    <?php create_cvss_dropdown("AccessVector") ?>
                                  </td>
                                  <td><img src="../images/helpicon.jpg" width="25" height="18" align="absmiddle" onClick="javascript:showHelp('AccessVectorHelp');"></td>
                                </tr>
                              </table></td>
                            </tr>
                            <tr>
                              <td>Attack Complexity</td>
                              <td class=""><table border="0" cellspacing="0" cellpadding="0">
                                  <tr>
                                    <td>
                                      <?php create_cvss_dropdown("AccessComplexity") ?>
                                    </td>
                                    <td><img src="../images/helpicon.jpg" width="25" height="18" align="absmiddle" onClick="javascript:showHelp('AccessComplexityHelp');"></td>
                                  </tr>
                                </table></td>
                            </tr>
                            <tr>
                              <td>Authentication</td>
                              <td><table border="0" cellspacing="0" cellpadding="0">
                                  <tr>
                                    <td>
                                      <?php create_cvss_dropdown("Authentication") ?>
                                    </td>
                                    <td><img src="../images/helpicon.jpg" width="25" height="18" align="absmiddle" onClick="javascript:showHelp('AuthenticationHelp');"></td>
                                  </tr>
                                </table></td>
                            </tr>
                            <tr>
                              <td colspan="2" class="style1">Impact Metrics</td>
                            </tr>
                            <tr>
                              <td>Confidentiality Impact</td>
                              <td><table border="0" cellspacing="0" cellpadding="0">
                                  <tr>
                                    <td>
                                      <?php create_cvss_dropdown("ConfImpact") ?>
                                    </td>
                                    <td><img src="../images/helpicon.jpg" width="25" height="18" align="absmiddle" onClick="javascript:showHelp('ConfImpactHelp');"></td>
                                  </tr>
                                </table></td>
                            </tr>
                            <tr>
                              <td>Integrity Impact</td>
                              <td><table border="0" cellspacing="0" cellpadding="0">
                                  <tr>
                                    <td>
                                      <?php create_cvss_dropdown("IntegImpact") ?>
                                    </td>
                                    <td><img src="../images/helpicon.jpg" width="25" height="18" align="absmiddle" onClick="javascript:showHelp('IntegImpactHelp');"></td>
                                  </tr>
                                </table></td>
                            </tr>
                            <tr>
                              <td>Availability Impact<br></td>
                              <td><table border="0" cellspacing="0" cellpadding="0">
                                  <tr>
                                    <td>
                                      <?php create_cvss_dropdown("AvailImpact") ?>
                                    </td>
                                    <td><img src="../images/helpicon.jpg" width="25" height="18" align="absmiddle" onClick="javascript:showHelp('AvailImpactHelp');"></td>
                                  </tr>
                                </table></td>
                            </tr>
                          </table></td>
                        </tr>
                        <tr bordercolor="#CCCCCC">
                          <td background="../images/cal-bg.jpg" bgcolor="#E6E2E1"class="style2"  style="background-repeat:no-repeat">&nbsp;&nbsp;&nbsp;Temporal Score Metrics</td>
                        </tr>
                        <tr>
                          <td  style="padding-left:5px;" ><table width="100%" border="0" cellspacing="1" cellpadding="1">
                            <tr>
                              <td> Exploitability</td>
                              <td><table border="0" cellspacing="0" cellpadding="0">
                                  <tr>
                                    <td>
                                      <?php create_cvss_dropdown("Exploitability", NULL, false) ?>
                                    </td>
                                    <td><img src="../images/helpicon.jpg" width="25" height="18" align="absmiddle" onClick="javascript:showHelp('ExploitabilityHelp');"></td>
                                  </tr>
                              </table></td>
                            </tr>
                            <tr>
                              <td> Remediation Level</td>
                              <td><table border="0" cellspacing="0" cellpadding="0">
                                  <tr>
                                    <td>
                                      <?php create_cvss_dropdown("RemediationLevel", NULL, false) ?>
                                    </td>
                                    <td><img src="../images/helpicon.jpg" width="25" height="18" align="absmiddle" onClick="javascript:showHelp('RemediationLevelHelp');"></td>
                                  </tr>
                              </table></td>
                            </tr>
                            <tr>
                              <td>Report Confidence</td>
                              <td><table border="0" cellspacing="0" cellpadding="0">
                                  <tr>
                                    <td>
                                      <?php create_cvss_dropdown("ReportConfidence", NULL, false) ?>
                                    </td>
                                    <td><img src="../images/helpicon.jpg" width="25" height="18" align="absmiddle" onClick="javascript:showHelp('ReportConfidenceHelp');"></td>
                                  </tr>
                              </table></td>
                            </tr>
                          </table></td>
                        </tr>
                        <tr bordercolor="#CCCCCC">
                          <td  background="../images/cal-bg.jpg" class="style2"><span class="style2" style="background-repeat:no-repeat">&nbsp;&nbsp;&nbsp;Environmental Score Metrics</span></td>
                        </tr>
                        <tr>
                          <td style="padding-left:5px;"><table width="100%" border="0" cellspacing="1" cellpadding="1">
                            <tr>
                              <td>Collateral Damage Potential</td>
                              <td><table border="0" cellspacing="0" cellpadding="0">
                                  <tr>
                                    <td>
                                      <?php create_cvss_dropdown("CollateralDamagePotential", NULL, false) ?>
                                    </td>
                                    <td><img src="../images/helpicon.jpg" width="25" height="18" align="absmiddle" onClick="javascript:showHelp('CollateralDamagePotentialHelp');" /></td>
                                  </tr>
                              </table></td>
                            </tr>
                            <tr>
                              <td> Target Distribution</td>
                              <td><table border="0" cellspacing="0" cellpadding="0">
                                  <tr>
                                    <td>
                                      <?php create_cvss_dropdown("TargetDistribution", NULL, false) ?>
                                    </td>
                                    <td><img src="../images/helpicon.jpg" width="25" height="18" align="absmiddle" onClick="javascript:showHelp('TargetDistributionHelp');" /></td>
                                  </tr>
                              </table></td>
                            </tr>
                            <tr>
                              <td colspan="2" class="style1"><strong>Impact Subscore Modifiers</strong></td>
                            </tr>
                            <tr>
                              <td> Confidentiality Requirement</td>
                              <td><table border="0" cellspacing="0" cellpadding="0">
                                  <tr>
                                    <td>
                                      <?php create_cvss_dropdown("ConfidentialityRequirement", NULL, false) ?>
                                    </td>
                                    <td><img src="../images/helpicon.jpg" width="25" height="18" align="absmiddle" onClick="javascript:showHelp('ConfidentialityRequirementHelp');" /></td>
                                  </tr>
                              </table></td>
                            </tr>
                            <tr>
                              <td> Integrity Requirement</td>
                              <td><table border="0" cellspacing="0" cellpadding="0">
                                  <tr>
                                    <td>
                                      <?php create_cvss_dropdown("IntegrityRequirement", NULL, false) ?>
                                    </td>
                                    <td><img src="../images/helpicon.jpg" width="25" height="18" align="absmiddle" onClick="javascript:showHelp('IntegrityRequirementHelp');" /></td>
                                  </tr>
                              </table></td>
                            </tr>
                            <tr>
                              <td> Availability Requirement</td>
                              <td><table border="0" cellspacing="0" cellpadding="0">
                                  <tr>
                                    <td>
                                      <?php create_cvss_dropdown("AvailabilityRequirement", NULL, false) ?>
                                    </td>
                                    <td><img src="../images/helpicon.jpg" width="25" height="18" align="absmiddle" onClick="javascript:showHelp('AvailabilityRequirementHelp');" /></td>
                                  </tr>
                              </table></td>
                            </tr>
                          </table></td>
                        </tr>
                        <tr>
                          <td height="5"></td>
                        </tr>
                    </table></td>
                  </tr>
                  <tr>
                    <td align="center">
<!--
                      <input name="btnCalculate" type="image" id="btnCalculate" src="../images/cal-cvss.jpg"><br />
-->
                      <input type="button" name="cvssSubmit" id="cvssSubmit" value="Submit" onclick="javascript: submitandclose();" />
                    </td>
                  </tr>
                  <tr>
                    <td align="center" height="5"></td>
                  </tr>
              </table></td>
            </tr>
          </table></td>
        </tr>
      </table></td>
  </tr>
</table>
</form>
</body>
</html>
