using Login.Models.DTOs;

namespace Login.Services
{
    public interface IAuthService
    {
        Task<bool> RegisterAsync(RegisterDto model);
        Task<LoginResponseDto> LoginAsync(LoginDto model);
        Task<bool> Enable2FAAsync(string userId, string otpCode);
        Task<bool> Disable2FAAsync(string userId, string otpCode);
        Task<bool> Is2FAEnabledAsync(string userId);
        Task<bool> VerifyEmailOtpAsync(string email, string token);
        Task<TwoFactorSetupDto> Get2FASetupAsync(string userId, string email);
        Task<bool> LogoutAsync(string userId);
        Task<UserProfileDto> GetUserProfileAsync(string userId);
    }
}