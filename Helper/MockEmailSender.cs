using Microsoft.AspNetCore.Identity.UI.Services;

namespace Login.Services
{
    /// <summary>
    /// Mock EmailSender for development/testing when real email service is not available
    /// </summary>
    public class MockEmailSender : IEmailSender
    {
        private readonly ILogger<MockEmailSender> _logger;

        public MockEmailSender(ILogger<MockEmailSender> logger)
        {
            _logger = logger;
        }

        public Task SendEmailAsync(string email, string subject, string htmlMessage)
        {
            // Log email content to console instead of sending
            _logger.LogInformation("=== MOCK EMAIL SENT ===");
            _logger.LogInformation("To: {Email}", email);
            _logger.LogInformation("Subject: {Subject}", subject);
            _logger.LogInformation("Body: {Body}", htmlMessage);
            _logger.LogInformation("======================");

            // In development console để dễ debug
            Console.WriteLine($"\n📧 [MOCK EMAIL] To: {email}");
            Console.WriteLine($"📋 Subject: {subject}");
            Console.WriteLine($"📄 Body: {htmlMessage}\n");

            return Task.CompletedTask;
        }
    }
}