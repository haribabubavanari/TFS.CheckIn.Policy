using Microsoft.TeamFoundation.Common;
using Microsoft.TeamFoundation.Framework.Server;
using Microsoft.TeamFoundation.VersionControl.Server;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SqlClient;
using System.Diagnostics;
using System.DirectoryServices.AccountManagement;
using System.Linq;
using System.Text.RegularExpressions;
using System.Net.Mail;

/// <summary>
/// This policy rejects the checkins into TFS if RR numbers in TFS comment doesn't validated against Service Manager. 
/// Policy is excluded for AD Group - "TFS Developers"
/// </summary>
namespace SCDMV.TFS.Comment.CheckinPolicy
{
    public class SMValidatePolicy : ISubscriber
    {
        public string Name
        {
            get
            {
                return "TFS.EnforceCheckInPolicies";
            }
        }

        public SubscriberPriority Priority
        {
            get
            {
                return SubscriberPriority.High;
            }
        }

       
        public EventNotificationStatus ProcessEvent(IVssRequestContext requestContext,
                                                    NotificationType notificationType,
                                                    object notificationEventArgs,
                                                    out int statusCode,
                                                    out string statusMessage,
                                                    out ExceptionPropertyCollection properties
                                                    )
        {
            statusCode = 0;
            properties = null;
            statusMessage = string.Empty;
            string missingRRList = string.Empty;
            bool isValidationFailed = false;
            string matchedRRList = string.Empty;
            List<string> _commentRelNum = new List<string>();

            try
            {

                #region Decision Point
                //Execute this logic only at the time of Checkin-DecisionPoint (Before check-in happens)
                if (notificationType == NotificationType.DecisionPoint && notificationEventArgs is CheckinNotification)
                {
                    var args = notificationEventArgs as CheckinNotification;
                    //Skip the policy for TFS Administrators Group
                    if (!isTFSAdminMember(args.ChangesetOwner.UniqueName))
                    {
                        if (!string.IsNullOrEmpty(args.Comment) && args.GetSubmittedItems(requestContext).Any(s => s.Contains("_Releases")))
                    {
                        //Skip the policy if the comment starts with any word from 'skiplist' in Config file
                        if (!SCDMV.TFS.Comment.CheckinPolicy.Properties.Settings.Default.SkipList.Cast<string>().ToList()
                             .Any(x => args.Comment.TrimStart().StartsWith(x, StringComparison.OrdinalIgnoreCase)))
                        {
                            //Get all RR Titles from user comment
                            _commentRelNum = GetRRTitles(args.Comment);
                            var files = args.GetSubmittedItems(requestContext);
                            foreach (string filePath in files)
                            {
                                if (filePath.Contains("_Releases"))
                                {
                                    string RelNum = string.Empty;
                                    string matchedCommentRRTitle = string.Empty;
                                    string[] _filePath = filePath.Split('/');

                                    if (_filePath[3].TrimStart().StartsWith("MR") || _filePath[3].TrimStart().StartsWith("HF"))
                                    {
                                        RelNum = Regex.Match(_filePath[3], @"(?<=((?i)MR(?-i)|(?i)HF(?-i))[^\w]*?[_]*?[^\w]*?)\d+").Value;
                                        matchedCommentRRTitle = _commentRelNum.FirstOrDefault(x => Regex.Match(x, @"(?<=((?i)MR(?-i)|(?i)HF(?-i))[^\w]*?[_]*?[^\w]*?)\d+").Value == RelNum);                                        
                                    }
                                    else
                                    {
                                        matchedCommentRRTitle = _commentRelNum.FirstOrDefault(y => y.Replace(" ", "").ToUpper().Contains(_filePath[3].Replace(" ", "").ToUpper()));                                      
                                    }

                                    if (matchedCommentRRTitle.IsNullOrEmpty())
                                    {
                                        if (!missingRRList.Contains(_filePath[3]))
                                        {
                                            missingRRList = string.Format("{0} {1}, ", missingRRList, _filePath[3]);
                                        }
                                        isValidationFailed = true;
                                    }
                                    else
                                    {                                       
                                        if (matchedRRList.IsNullOrEmpty()) { matchedRRList = "You entered - "; }
                                        matchedCommentRRTitle = "RR"+Regex.Match(matchedCommentRRTitle, @"(?<=(.*?)(?i)RR(?-i)[^\w]*?[_]*?[^\w]*?)\d+").Value;

                                        matchedRRList = matchedRRList + matchedCommentRRTitle + "--" + _filePath[3] + ", ";
                                    }
                                }
                            }

                            if (isValidationFailed)
                                    {
                                        statusMessage = string.Format("Check-in Rejected, Please enter valid RR number for all releases that you are checking in.\n\n{1}\nRelease Name's that are missing RR's-{0}\n\nIf you enter all valid RR's, please make sure the RR Title has release name(listed as above) in it\nFor further assistance, please email - CM@scdmv.net", missingRRList, matchedRRList);
                                        return EventNotificationStatus.ActionDenied;
                                    }                           
                        }
                    }
                    }
                }

                #endregion

                #region Notification Point

                if (notificationType == NotificationType.Notification && notificationEventArgs is CheckinNotification)
                {
                    var args = notificationEventArgs as CheckinNotification;

                    if (!string.IsNullOrEmpty(args.Comment) && args.GetSubmittedItems(requestContext).Any(s => s.Contains("_Releases")))
                    {
                        if (SCDMV.TFS.Comment.CheckinPolicy.Properties.Settings.Default.SkipList.Cast<string>().ToList()
                        .Any(x => args.Comment.TrimStart().StartsWith(x, StringComparison.OrdinalIgnoreCase)))
                        {
                            //Notify CMTeam
                            string changes = string.Join("<br />", args.GetSubmittedItems(requestContext).ToArray());
                            sendEmail(args.ChangesetOwner.UniqueName, args.Changeset.ToString(), args.Comment, changes);
                        }
                    }
                }


                #endregion
                return EventNotificationStatus.ActionPermitted;

            }

            catch (Exception ex)
            {
                sendEmail(string.Empty, string.Empty, ex.ToString(), string.Empty);
                // log the error and fail the check in
                statusMessage = "Error in plug in '" + this.Name + "', error details: " + ex;
                EventLog.WriteEntry("SCDMV.TFS.Comment.CheckinPolicy", statusMessage, EventLogEntryType.Error);
                return EventNotificationStatus.ActionDenied;
            }
        }

        private List<string> GetRRTitles(string comment)
        {
            List<string> listTitles = new List<string>();
            //Parse all RR numbers from user comment
            var rrNumbers = Regex.Matches(comment, @"(?<=(.*?)(?i)RR(?-i)[^\w]*?[_]*?[^\w]*?)\d+");

            foreach (var rrnum in rrNumbers)
            {
                //Get Title of each RR in TFS comment
                string rrTitle = GetRRTitle(rrnum.ToString().Trim());
                //Extract only the release number followed by MR or HF from RR Title
                if (!string.IsNullOrEmpty(rrTitle))
                {
                    listTitles.Add(rrTitle);
                }
            }

            return listTitles;
        }
        private void sendEmail(string user, string id, string comment, string changes)
        {
            MailMessage mail = new MailMessage("cm@scdmv.net", "CMTeam@scdmv.net");

            using (PrincipalContext ctx = new PrincipalContext(ContextType.Domain, "DOMAIN"))
            {
                UserPrincipal cp = UserPrincipal.FindByIdentity(ctx, user);
                mail.CC.Add(new MailAddress(cp.EmailAddress));
            }

            SmtpClient client = new SmtpClient();
            client.Port = 25;
            client.DeliveryMethod = SmtpDeliveryMethod.Network;
            client.UseDefaultCredentials = false;
            client.Host = "SMTP.DOMAIN.int";
            //"SMTP.DOMAIN.int";
            mail.IsBodyHtml = true;

            if (user.IsNullOrEmpty())
            {
                mail.Subject = "Exception Occurred in TFS Check-in policy";
                mail.Body = "<html><body><p>Exception Occurred in TFS Check-in policy</p><br /><br /><p>Exceptipn Message:</p><br >" + comment + "</ body ></ html > ";
            }
            else
            {
                mail.Subject = "TFS Check-in policy is overridden";
                mail.Body = "<html><body><p>TFS Check-in policy is overridden</p><table><tr style='border:1px black'><td>User Name: </td><td>" + user + "</td></tr><tr style='border:1px black'><td>ChangeSet Number: </td><td>" + id + "</td></tr><tr style='border:1px black'><td>Comment: </td><td>" + comment + "</td></tr><tr style='border:1px blac'><td>File Paths: </td><td><p>" + changes + "</p></td></tr></table><br/><br/><a href='http://TFSSErver:8080/tfs/Project/_versionControl/changeset/" + id + "'>Click here</a> to view the changeset details.</ body ></ html > ";
            }
            client.Send(mail);
        }

        private bool isTFSAdminMember(string username)
        {
            PrincipalContext ctx = new PrincipalContext(ContextType.Domain, "DOMAIN.INT");
            UserPrincipal user = UserPrincipal.FindByIdentity(ctx, username);
            GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, "_TFS Administrators");

            if (user != null)
            {   // check if user is member of that group
                if (user.IsMemberOf(group)) return true;
            }
            return false;
        }
        private static string GetRRTitle(string rrNumber)
        {
            string sqlCmd = @"select DisplayName from MTV_System$WorkItem$ReleaseRecord where DisplayName LIKE '%RR" + rrNumber + "%'";
            string ConnectionString = SCDMV.TFS.Comment.CheckinPolicy.Properties.Settings.Default.ConnString;
            using (SqlConnection connection = new SqlConnection(ConnectionString))
            {
                try
                {
                    using (SqlCommand cmdCheck = new SqlCommand(sqlCmd, connection))
                    {
                        cmdCheck.Parameters.AddWithValue("rrNumber", rrNumber);
                        connection.Open();

                        string releaseRectitle = (string)cmdCheck.ExecuteScalar();
                        if (!string.IsNullOrEmpty(releaseRectitle))
                            return releaseRectitle;
                        else
                            return string.Empty;
                    }
                }
                finally
                {
                    if (connection.State == ConnectionState.Open) connection.Close();
                }
            }
        }

        public Type[] SubscribedTypes()
        {
            return new[] { typeof(CheckinNotification) };
        }
    }
}