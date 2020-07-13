// Based on https://docs.microsoft.com/en-us/aspnet/web-api/overview/security/basic-authentication

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http.Headers;
using System.Text;
using System.Web;
using System.Web.Configuration;

namespace AuthorizedTester
{
    public class TestUsersModule : IHttpModule
    {
        private const string Realm = "TestEnvironment";
        private bool ModuleEnabled { get; set; }
        private List<string> IPWhitelist { get; set; }
        private List<string> UserWhitelist { get; set; }
        private List<string> DomainsBlacklist { get; set; }

        public void Dispose() { }

        public void Init(HttpApplication application)
        {
            LoadSettings();

            if (ModuleEnabled)
            {
                application.BeginRequest += Application_BeginRequest;
            }
        }

        private void LoadSettings()
        {
            var module = WebConfigurationManager.AppSettings["TestUsersModule.Enabled"];
            if (module != null && bool.TryParse(module, out bool enableModule))
            {
                ModuleEnabled = enableModule;
            }
            else
            {
                // Setting not found or invalid value, turn it on anyway
                ModuleEnabled = true;
            }

            if (!ModuleEnabled) return; // No need to read other settings if the module is not turned on.

            var ips = WebConfigurationManager.AppSettings["TestUsersModule.Whitelist.IP"];
            if (ips != null)
            {
                IPWhitelist = new List<string>(ips.Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries));
            }

            var users = WebConfigurationManager.AppSettings["TestUsersModule.Whitelist.Users"];
            if (users != null)
            {
                UserWhitelist = new List<string>(users.Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries));
            }

            var domains = WebConfigurationManager.AppSettings["TestUsersModule.Blacklist.Domains"];
            if (domains != null)
            {
                DomainsBlacklist = new List<string>(domains.Split(new char[] { '|' }, StringSplitOptions.RemoveEmptyEntries));
            }
        }

        private void Application_BeginRequest(object sender, EventArgs e)
        {
            HttpApplication application = (HttpApplication)sender;
            HttpRequest request = application.Context.Request;
            HttpResponse response = application.Context.Response;

            if (DomainsBlacklist == null || !DomainsBlacklist.Any() || (request.Url.HostNameType == UriHostNameType.Dns && DomainsBlacklist.Contains(request.Url.Host)))
            {
                if (IPWhitelist != null && IPWhitelist.Contains(request.UserHostAddress))
                {
                    // IP found, do nothing
                    response.Headers.Add("X-TestUser", "Access by IP");
                    return;
                }

                if (UserWhitelist != null)
                {
                    string authHeader = request.Headers["Authorization"];

                    if (authHeader != null)
                    {
                        var authHeaderVal = AuthenticationHeaderValue.Parse(authHeader);

                        // RFC 2617 sec 1.2, "scheme" name is case-insensitive
                        if (authHeaderVal.Scheme.Equals("basic", StringComparison.OrdinalIgnoreCase) && authHeaderVal.Parameter != null)
                        {
                            if (DoesUserExist(authHeaderVal.Parameter))
                            {
                                // User is valid, do nothing
                                response.Headers.Add("X-TestUser", "Access by credentials");
                                return;
                            }
                        }
                    }
                    else
                    {
                        // No authenticationheader found, request a username and password
                        response.Clear();
                        response.StatusCode = 401;
                        response.Headers.Add("WWW-Authenticate", string.Format("Basic realm=\"{0}\"", Realm));
                        response.End();
                    }
                }

                // No whitelisted IP or user found, block access
                response.Clear();
                response.StatusCode = 403;
                response.StatusDescription = "Forbidden";
                response.End();
            }
        }

        private bool DoesUserExist(string credentials)
        {
            try
            {
                var encoding = Encoding.GetEncoding("iso-8859-1");
                credentials = encoding.GetString(Convert.FromBase64String(credentials));

                if (UserWhitelist.Contains(credentials))
                {
                    return true;
                }
            }
            catch (FormatException) { }

            return false;
        }
    }
}
