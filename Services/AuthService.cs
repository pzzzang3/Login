using Login.Models;
using Login.Models.DTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using OtpNet;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Login.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;

        public AuthService(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        public async Task<bool> RegisterAsync(RegisterDto dto)
        {
            var user = new ApplicationUser
            {
                UserName = dto.Email,
                Email = dto.Email
            };

            var result = await _userManager.CreateAsync(user, dto.Password);
            return result.Succeeded;
        }

        public async Task<string> LoginAsync(LoginDto dto)
        {
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.Email == dto.Email);
            if (user == null)
                throw new Exception("Email hoặc mật khẩu không đúng.");

            // Kiểm tra mật khẩu
            var passwordValid = await _userManager.CheckPasswordAsync(user, dto.Password);
            if (!passwordValid)
                throw new Exception("Email hoặc mật khẩu không đúng.");

            // Nếu 2FA bật
            if (user.TwoFactorEnabled)
            {
                if (string.IsNullOrWhiteSpace(dto.TwoFactorCode))
                    throw new Exception("Tài khoản đã bật 2FA. Vui lòng nhập mã OTP.");

                // Xác thực mã OTP (Google Authenticator)
                if (!VerifyOtp(user.TwoFactorSecretKey, dto.TwoFactorCode))
                    throw new Exception("Mã OTP không hợp lệ.");
            }

            // Tạo JWT
            return await GenerateJwtToken(user);
        }

        public async Task<bool> Enable2FAAsync(string userId, string otpCode)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return false;

            // Nếu user chưa có secret key → tạo mới
            if (string.IsNullOrEmpty(user.TwoFactorSecretKey))
            {
                var secret = KeyGeneration.GenerateRandomKey(20);
                user.TwoFactorSecretKey = Base32Encoding.ToString(secret);
                await _userManager.UpdateAsync(user);
            }

            // Xác minh OTP
            if (!VerifyOtp(user.TwoFactorSecretKey, otpCode))
                return false;

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            return true;
        }

        public async Task<bool> Disable2FAAsync(string userId, string otpCode)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return false;

            // Phải xác minh OTP trước khi tắt
            if (!VerifyOtp(user.TwoFactorSecretKey, otpCode))
                return false;

            user.TwoFactorEnabled = false;
            user.TwoFactorSecretKey = null;
            await _userManager.UpdateAsync(user);

            return true;
        }

        public async Task<bool> Is2FAEnabledAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            return user?.TwoFactorEnabled ?? false;
        }

        public async Task<bool> VerifyEmailOtpAsync(string email, string token)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) return false;

            var res = await _userManager.ConfirmEmailAsync(user, token);
            return res.Succeeded;
        }

        public async Task<TwoFactorSetupDto> Get2FASetupAsync(string userId, string email)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                throw new Exception("Không tìm thấy người dùng");

            // Tạo secret key nếu chưa có
            if (string.IsNullOrEmpty(user.TwoFactorSecretKey))
            {
                var secret = KeyGeneration.GenerateRandomKey(20);
                user.TwoFactorSecretKey = Base32Encoding.ToString(secret);
                await _userManager.UpdateAsync(user);
            }

            var appName = _configuration["AppName"] ?? "MyApp";
            var qrCodeUrl = $"otpauth://totp/{Uri.EscapeDataString(appName)}:{Uri.EscapeDataString(email)}?secret={user.TwoFactorSecretKey}&issuer={Uri.EscapeDataString(appName)}";

            return new TwoFactorSetupDto
            {
                SecretKey = user.TwoFactorSecretKey,
                QrCodeUrl = qrCodeUrl,
                ManualEntryKey = user.TwoFactorSecretKey
            };
        }

        // ---------- helpers ----------
        private async Task<string> GenerateJwtToken(ApplicationUser user)
        {
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var authSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])
            );

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private bool VerifyOtp(string base32Secret, string code)
        {
            if (string.IsNullOrEmpty(base32Secret)) return false;

            try
            {
                var secret = Base32Encoding.ToBytes(base32Secret);
                var totp = new Totp(secret);
                return totp.VerifyTotp(code, out _, new VerificationWindow(2, 2));
            }
            catch
            {
                return false;
            }
        }
    }
}