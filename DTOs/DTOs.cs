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
        public string? LastName { get; set; }

        [Phone(ErrorMessage = "Số điện thoại không hợp lệ")]
        public string? PhoneNumber { get; set; }
    }

    // DTO cho response đăng ký
    public class RegisterResponseDto
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    // DTO cho xác thực email
    public class VerifyEmailDto
    {
        [Required(ErrorMessage = "Email là bắt buộc")]
        [EmailAddress(ErrorMessage = "Email không hợp lệ")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Mã OTP là bắt buộc")]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "Mã OTP phải có 6 số")]
        public string OtpCode { get; set; } = string.Empty;
    }

    // DTO cho response xác thực email
    public class VerifyEmailResponseDto
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    // DTO cho gửi lại email OTP
    public class ResendEmailOtpDto
    {
        [Required(ErrorMessage = "Email là bắt buộc")]
        [EmailAddress(ErrorMessage = "Email không hợp lệ")]
        public string Email { get; set; } = string.Empty;
    }

    // DTO cho response gửi lại email OTP
    public class ResendEmailOtpResponseDto
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    // DTO cho đăng nhập
    public class LoginDto
    {
        [Required(ErrorMessage = "Email là bắt buộc")]
        [EmailAddress(ErrorMessage = "Email không hợp lệ")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Mật khẩu là bắt buộc")]
        public string Password { get; set; } = string.Empty;

        // Ghi nhớ đăng nhập
        public bool RememberMe { get; set; } = false;
    }

    // DTO cho response đăng nhập
    public class LoginResponseDto
    {
        public string? Token { get; set; }
        public bool RequiresTwoFactor { get; set; }
        public string? LoginSessionId { get; set; } // Session tạm cho 2FA
        public string Message { get; set; } = string.Empty;
    }

    // DTO cho xác nhận đăng nhập 2FA
    public class ConfirmLoginDto
    {
        [Required(ErrorMessage = "Session ID là bắt buộc")]
        public string LoginSessionId { get; set; } = string.Empty;

        [Required(ErrorMessage = "Mã OTP là bắt buộc")]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "Mã OTP phải có 6 số")]
        public string OtpCode { get; set; } = string.Empty;

        public bool RememberMe { get; set; } = false;
    }

    // DTO cho response xác nhận đăng nhập
    public class ConfirmLoginResponseDto
    {
        public bool Success { get; set; }
        public string? Token { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    // DTO cho toggle 2FA
    public class Toggle2FADto
    {
        [Required(ErrorMessage = "Mã OTP từ ứng dụng Authenticator là bắt buộc")]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "Mã OTP phải có 6 số")]
        public string OtpCode { get; set; } = string.Empty;
    }

    // Response DTO cho toggle 2FA
    public class Toggle2FAResponseDto
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public bool IsEnabled { get; set; }
    }

    // DTO cho QR code 2FA
    public class TwoFactorQRDto
    {
        public string QrCodeBase64 { get; set; } = string.Empty;
    }

    // DTO cho setup 2FA (deprecated - sẽ được thay thế bởi TwoFactorQRDto)
    public class TwoFactorSetupDto
    {
        public string SecretKey { get; set; } = string.Empty;
        public string QrCodeUrl { get; set; } = string.Empty;
        public string ManualEntryKey { get; set; } = string.Empty;
    }

    // DTO cho login session (dùng nội bộ)
    public class LoginSession
    {
        public string SessionId { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public DateTime CreatedAt { get; set; }
        public DateTime ExpiresAt { get; set; }
        public bool RememberMe { get; set; }
    }
}