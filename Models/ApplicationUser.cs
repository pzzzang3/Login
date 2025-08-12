using Microsoft.AspNetCore.Identity;

public class ApplicationUser : IdentityUser
{
    // Sử dụng TwoFactorEnabled có sẵn từ IdentityUser, không cần IsTwoFactorEnabled
    // public bool IsTwoFactorEnabled { get; set; } // Xóa dòng này

    public string? AuthenticatorKey { get; set; }
    public DateTime? EmailConfirmationTokenExpiry { get; set; }
    public string? EmailOtpCode { get; set; }
    public DateTime? EmailOtpExpiry { get; set; }
    public string? TwoFactorSecretKey { get; set; }

    // Additional properties
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }
}