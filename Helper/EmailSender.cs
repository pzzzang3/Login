using Microsoft.AspNetCore.Identity.UI.Services;

namespace Login.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly IConfiguration _config;
        private readonly ILogger<EmailSender> _logger;

        public EmailSender(IConfiguration config, ILogger<EmailSender> logger)
        {
            _config = config;
            _logger = logger;
        }

        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            try
            {
                var host = _config["EmailSettings:Host"];
                var port = int.Parse(_config["EmailSettings:Port"] ?? "587");
                var username = _config["EmailSettings:Username"];
                var password = _config["EmailSettings:Password"];
                var enableSsl = bool.Parse(_config["EmailSettings:EnableSsl"] ?? "true");
                var displayName = _config["EmailSettings:DisplayName"] ?? "Auth2FA App";

                if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
                {
                    _logger.LogError("Email configuration is incomplete. Please check appsettings.json");
                    throw new InvalidOperationException("Email configuration is incomplete");
                }

                using var smtpClient = new System.Net.Mail.SmtpClient(host)
                {
                    Port = port,
                    Credentials = new System.Net.NetworkCredential(username, password),
                    EnableSsl = enableSsl,
                    DeliveryMethod = System.Net.Mail.SmtpDeliveryMethod.Network,
                    UseDefaultCredentials = false
                };

                using var mailMessage = new System.Net.Mail.MailMessage
                {
                    From = new System.Net.Mail.MailAddress(username, displayName),
                    Subject = subject,
                    Body = htmlMessage,
                    IsBodyHtml = true
                };

                mailMessage.To.Add(email);

                await smtpClient.SendMailAsync(mailMessage);
                _logger.LogInformation("Email sent successfully to {Email}", email);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to send email to {Email}: {Error}", email, ex.Message);

                // Trong development, có thể không throw exception để không làm gián đoạn flow
                var environment = _config.GetValue<string>("Environment") ??
                                _config.GetValue<string>("ASPNETCORE_ENVIRONMENT") ?? "Production";

                if (environment == "Development")
                {
                    _logger.LogWarning("Email sending failed in development mode - continuing without sending email");
                }
                else
                {
                    throw;
                }
            }
        }
    }
}