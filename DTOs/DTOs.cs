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

    // DTO cho đăng nhập - đã loại bỏ trường TwoFactorCode
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

    // DTO cho xác minh 2FA khi đăng nhập (API riêng)
    public class Verify2FADto
    {
        [Required(ErrorMessage = "Email là bắt buộc")]
        [EmailAddress(ErrorMessage = "Email không hợp lệ")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Mật khẩu là bắt buộc")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Mã OTP là bắt buộc")]
        [StringLength(6, MinimumLength = 6, ErrorMessage = "Mã OTP phải có 6 số")]
        public string TwoFactorCode { get; set; } = string.Empty;

        public bool RememberMe { get; set; } = false;
    }

    public class LoginResponseDto
    {
        public string? Token { get; set; }
        public bool RequiresTwoFactor { get; set; }
        public string Message { get; set; } = string.Empty;
    }

    // DTO cho toggle 2FA - Chỉ cần mã OTP để xác thực
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

    // Xóa TwoFactorStatusDto vì không cần API riêng xem trạng thái
    // Thông tin trạng thái 2FA sẽ có trong UserProfileDto
}