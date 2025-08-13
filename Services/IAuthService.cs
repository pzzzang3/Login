using Login.Models.DTOs;

namespace Login.Services
{
    public interface IAuthService
    {
        // Đăng ký và xác thực email
        Task<RegisterResponseDto> RegisterAsync(RegisterDto model);
        Task<VerifyEmailResponseDto> VerifyEmailAsync(VerifyEmailDto model);
        Task<ResendEmailOtpResponseDto> ResendEmailOtpAsync(string email);

        // Đăng nhập
        Task<LoginResponseDto> LoginAsync(LoginDto model);
        Task<ConfirmLoginResponseDto> ConfirmLoginAsync(ConfirmLoginDto model);

        // 2FA và profile
        Task<Toggle2FAResponseDto> Toggle2FAAsync(string userId, string otpCode);
        Task<TwoFactorQRDto> Get2FAQRCodeAsync(string userId, string email);
        Task<UserProfileDto> GetUserProfileAsync(string userId);

        // Đăng xuất
        Task<bool> LogoutAsync(string userId);
    }
}