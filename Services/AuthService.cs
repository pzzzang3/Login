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
                Email = dto.Email,
                TwoFactorEnabled = false, // Mặc định tắt 2FA
                FirstName = dto.FullName?.Split(' ').FirstOrDefault(),
                LastName = dto.FullName?.Contains(' ') == true ?
                    string.Join(" ", dto.FullName.Split(' ').Skip(1)) : null,
                PhoneNumber = dto.PhoneNumber
            };

            var result = await _userManager.CreateAsync(user, dto.Password);
            return result.Succeeded;
        }

        public async Task<LoginResponseDto> LoginAsync(LoginDto dto)
        {
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.Email == dto.Email);
            if (user == null)
                throw new Exception("Email hoặc mật khẩu không đúng.");

            // Kiểm tra mật khẩu
            var passwordValid = await _userManager.CheckPasswordAsync(user, dto.Password);
            if (!passwordValid)
                throw new Exception("Email hoặc mật khẩu không đúng.");

            // Cập nhật thời gian đăng nhập cuối
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Nếu 2FA tắt → trả token luôn
            if (!user.TwoFactorEnabled)
            {
                var token = await GenerateJwtToken(user);
                return new LoginResponseDto
                {
                    Token = token,
                    RequiresTwoFactor = false,
                    Message = "Đăng nhập thành công"
                };
            }

            // Nếu 2FA bật
            if (string.IsNullOrWhiteSpace(dto.TwoFactorCode))
            {
                return new LoginResponseDto
                {
                    RequiresTwoFactor = true,
                    Message = "Tài khoản đã bật 2FA. Vui lòng nhập mã OTP."
                };
            }

            // Xác thực mã OTP
            if (!VerifyOtp(user.TwoFactorSecretKey, dto.TwoFactorCode))
            {
                throw new Exception("Mã OTP không hợp lệ.");
            }

            // Tạo JWT sau khi xác thực 2FA thành công
            var jwtToken = await GenerateJwtToken(user);
            return new LoginResponseDto
            {
                Token = jwtToken,
                RequiresTwoFactor = false,
                Message = "Đăng nhập thành công"
            };
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

            // Bật 2FA
            user.TwoFactorEnabled = true;
            await _userManager.UpdateAsync(user);

            return true;
        }

        public async Task<bool> Disable2FAAsync(string userId, string otpCode)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null) return false;

            // Nếu 2FA chưa bật thì không cần làm gì
            if (!user.TwoFactorEnabled)
                return true;

            // Phải xác minh OTP trước khi tắt
            if (!VerifyOtp(user.TwoFactorSecretKey, otpCode))
                return false;

            // Tắt 2FA và xóa secret key
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

            var result = await _userManager.ConfirmEmailAsync(user, token);
            return result.Succeeded;
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

        public async Task<bool> LogoutAsync(string userId)
        {
            // Có thể thêm logic invalidate token hoặc blacklist token ở đây
            // Hiện tại chỉ return true vì JWT stateless
            return await Task.FromResult(true);
        }

        public async Task<UserProfileDto> GetUserProfileAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                throw new Exception("Không tìm thấy người dùng");

            return new UserProfileDto
            {
                Id = user.Id,
                Email = user.Email,
                FullName = $"{user.FirstName} {user.LastName}".Trim(),
                PhoneNumber = user.PhoneNumber,
                Is2FAEnabled = user.TwoFactorEnabled,
                CreatedAt = user.CreatedAt,
                LastLoginAt = user.LastLoginAt
            };
        }

        // ---------- Private Methods ----------
        private async Task<string> GenerateJwtToken(ApplicationUser user)
        {
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
                new Claim(ClaimTypes.Name, user.UserName ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat,
                    new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString(),
                    ClaimValueTypes.Integer64)
            };

            var authSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_configuration["Jwt:Key"] ?? throw new InvalidOperationException("JWT Key not found"))
            );

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                expires: DateTime.UtcNow.AddHours(24), // Token có hiệu lực 24 giờ
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private bool VerifyOtp(string? base32Secret, string code)
        {
            if (string.IsNullOrEmpty(base32Secret) || string.IsNullOrEmpty(code))
                return false;

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