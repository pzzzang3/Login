using System.ComponentModel.DataAnnotations;

namespace Login.Models.DTOs
{
    public class Disable2FADto
    {
        [Required(ErrorMessage = "Mã OTP là bắt buộc")]
        public string OtpCode { get; set; } = string.Empty;
    }
}