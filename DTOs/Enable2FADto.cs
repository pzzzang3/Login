using System.ComponentModel.DataAnnotations;

namespace Login.Models.DTOs // Đổi từ Login.Models thành Login.Models.DTOs
{
    public class Enable2FADto
    {
        [Required(ErrorMessage = "Mã OTP là bắt buộc")]
        public string OtpCode { get; set; } = string.Empty; // Đổi từ OTPCode thành OtpCode
    }
}