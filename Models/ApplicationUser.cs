using Microsoft.AspNetCore.Identity;

public class ApplicationUser : IdentityUser
{
    // Không cần IsTwoFactorEnabled vì sử dụng TwoFactorEnabled có sẵn từ IdentityUser

    public string? AuthenticatorKey { get; set; }
    public DateTime? EmailConfirmationTokenExpiry { get; set; }
    public string? EmailOtpCode { get; set; }
    public DateTime? EmailOtpExpiry { get; set; }

    // Secret key cho 2FA - giữ cố định để QR code không thay đổi
    public string? TwoFactorSecretKey { get; set; }

    // Additional properties
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }
}