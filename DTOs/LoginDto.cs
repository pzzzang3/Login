using System.ComponentModel.DataAnnotations;

namespace Login.Models.DTOs
{
    public class LoginDto
    {
        [Required(ErrorMessage = "Email là bắt buộc")]
        [EmailAddress(ErrorMessage = "Email không hợp lệ")]
        public string Email { get; set; } = string.Empty;

        [Required(ErrorMessage = "Mật khẩu là bắt buộc")]
        public string Password { get; set; } = string.Empty;

        // Dùng khi tài khoản đã bật 2FA
        public string? TwoFactorCode { get; set; }

        // Ghi nhớ đăng nhập
        public bool RememberMe { get; set; } = false;
    }
}