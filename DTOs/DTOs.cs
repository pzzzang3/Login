using System.ComponentModel.DataAnnotations;

namespace Login.Models.DTOs
{
    // DTO cho đăng ký
    public class RegisterDto
    {
        [Required(ErrorMessage = "Email là bắt buộc")]
        [EmailAddress(ErrorMessage = "Email không hợp lệ")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Mật khẩu là bắt buộc")]
        [MinLength(6, ErrorMessage = "Mật khẩu phải có ít nhất 6 ký tự")]
        public string Password { get; set; } = string.Empty;

        // Thêm thông tin tùy chọn
        public string? FullName { get; set; }

        [Phone(ErrorMessage = "Số điện thoại không hợp lệ")]
        public string? PhoneNumber { get; set; }
    }

    // DTO cho đăng nhập
    public class LoginDto
    {
        [Required(ErrorMessage = "Email là bắt buộc")]
        [EmailAddress(ErrorMessage = "Email không hợp lệ")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Mật khẩu là bắt buộc")]
        public string Password { get; set; } = string.Empty;

        // Mã OTP (chỉ cần khi đã bật 2FA)
        public string? TwoFactorCode { get; set; }

        // Ghi nhớ đăng nhập
        public bool RememberMe { get; set; } = false;
    }

    public class LoginResponseDto
    {
        public string? Token { get; set; }
        public bool RequiresTwoFactor { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    // DTO cho bật 2FA
    public class Enable2FADto
    {
        [Required(ErrorMessage = "Mã OTP là bắt buộc")]
        public string OtpCode { get; set; } = string.Empty;
    }

    // DTO cho tắt 2FA
    public class Disable2FADto
    {
        [Required(ErrorMessage = "Mã OTP là bắt buộc")]
        public string OtpCode { get; set; } = string.Empty;
    }

    // DTO cho setup 2FA (QR code, secret key)
    public class TwoFactorSetupDto
    {
        public string SecretKey { get; set; } = string.Empty;
        public string QrCodeUrl { get; set; } = string.Empty;
        public string ManualEntryKey { get; set; } = string.Empty;
    }

    // DTO cho trạng thái 2FA
    public class TwoFactorStatusDto
    {
        public bool IsEnabled { get; set; }
        public bool HasSecretKey { get; set; }
    }
}