using Login.Models.DTOs;

namespace Login.Services
{
    public interface IAuthService
    {
        Task<bool> RegisterAsync(RegisterDto model);
        Task<LoginResponseDto> LoginAsync(LoginDto model);
        Task<LoginResponseDto> Verify2FAAsync(Verify2FADto model);
        Task<Toggle2FAResponseDto> Toggle2FAAsync(string userId, bool enable);
        Task<bool> VerifyEmailOtpAsync(string email, string token);
        Task<TwoFactorQRDto> Get2FAQRCodeAsync(string userId, string email);
        Task<bool> LogoutAsync(string userId);
        Task<UserProfileDto> GetUserProfileAsync(string userId);
    }
}