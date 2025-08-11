using Microsoft.AspNetCore.Identity;

public class ApplicationUser : IdentityUser
{
    // Properties for 2FA
    public bool IsTwoFactorEnabled { get; set; }
    public string? AuthenticatorKey { get; set; }
    public DateTime? EmailConfirmationTokenExpiry { get; set; }
    public string? EmailOtpCode { get; set; }
    public DateTime? EmailOtpExpiry { get; set; }
    public string? TwoFactorSecretKey { get; set; }


    // Additional properties you might need
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }
}