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
                TwoFactorEnabled = false,
                FirstName = dto.FullName?.Split(' ').FirstOrDefault(),
                LastName = dto.FullName?.Contains(' ') == true ?
                    string.Join(" ", dto.FullName.Split(' ').Skip(1)) : null,
                PhoneNumber = dto.PhoneNumber,
                EmailConfirmed = true
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

            // Nếu 2FA bật → yêu cầu sử dụng API verify-2fa
            return new LoginResponseDto
            {
                RequiresTwoFactor = true,
                Message = "Tài khoản đã bật 2FA. Vui lòng sử dụng API verify-2fa với mã OTP."
            };
        }

        public async Task<LoginResponseDto> Verify2FAAsync(Verify2FADto dto)
        {
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.Email == dto.Email);
            if (user == null)
                throw new Exception("Email hoặc mật khẩu không đúng.");

            // Kiểm tra mật khẩu
            var passwordValid = await _userManager.CheckPasswordAsync(user, dto.Password);
            if (!passwordValid)
                throw new Exception("Email hoặc mật khẩu không đúng.");

            // Kiểm tra xem có bật 2FA không
            if (!user.TwoFactorEnabled)
                throw new Exception("Tài khoản chưa bật 2FA. Vui lòng sử dụng API login thông thường.");

            // Xác thực mã OTP
            if (!VerifyOtp(user.TwoFactorSecretKey, dto.TwoFactorCode))
                throw new Exception("Mã OTP không hợp lệ.");

            // Cập nhật thời gian đăng nhập cuối
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Tạo JWT sau khi xác thực 2FA thành công
            var token = await GenerateJwtToken(user);
            return new LoginResponseDto
            {
                Token = token,
                RequiresTwoFactor = false,
                Message = "Đăng nhập với 2FA thành công"
            };
        }

        public async Task<Toggle2FAResponseDto> Toggle2FAAsync(string userId, string otpCode)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return new Toggle2FAResponseDto
                {
                    Success = false,
                    Message = "Không tìm thấy người dùng"
                };

            // Tạo secret key nếu chưa có (cần thiết để verify OTP)
            if (string.IsNullOrEmpty(user.TwoFactorSecretKey))
            {
                var secret = KeyGeneration.GenerateRandomKey(20);
                user.TwoFactorSecretKey = Base32Encoding.ToString(secret);
                await _userManager.UpdateAsync(user);
            }

            // Xác thực mã OTP trước khi thực hiện toggle
            if (!VerifyOtp(user.TwoFactorSecretKey, otpCode))
            {
                return new Toggle2FAResponseDto
                {
                    Success = false,
                    Message = "Mã OTP không hợp lệ. Vui lòng kiểm tra lại ứng dụng Authenticator."
                };
            }

            // Toggle trạng thái 2FA (ngược lại với trạng thái hiện tại)
            var newTwoFactorStatus = !user.TwoFactorEnabled;

            if (newTwoFactorStatus)
            {
                // Bật 2FA
                await _userManager.SetTwoFactorEnabledAsync(user, true);

                return new Toggle2FAResponseDto
                {
                    Success = true,
                    Message = "Đã bật 2FA thành công! Tài khoản của bạn giờ đây được bảo vệ tốt hơn.",
                    IsEnabled = true
                };
            }
            else
            {
                // Tắt 2FA (không xóa secret key để giữ QR code cố định)
                await _userManager.SetTwoFactorEnabledAsync(user, false);

                return new Toggle2FAResponseDto
                {
                    Success = true,
                    Message = "Đã tắt 2FA thành công. Khuyến nghị bật lại để tăng cường bảo mật.",
                    IsEnabled = false
                };
            }
        }

        public async Task<bool> VerifyEmailOtpAsync(string email, string token)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) return false;

            var result = await _userManager.ConfirmEmailAsync(user, token);
            return result.Succeeded;
        }

        public async Task<TwoFactorQRDto> Get2FAQRCodeAsync(string userId, string email)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                throw new Exception("Không tìm thấy người dùng");

            // Tạo secret key nếu chưa có (và giữ cố định cho tài khoản này)
            if (string.IsNullOrEmpty(user.TwoFactorSecretKey))
            {
                var secret = KeyGeneration.GenerateRandomKey(20);
                user.TwoFactorSecretKey = Base32Encoding.ToString(secret);
                await _userManager.UpdateAsync(user);
            }

            var appName = _configuration["AppName"] ?? "Auth2FA App";
            var qrCodeUrl = $"otpauth://totp/{Uri.EscapeDataString(appName)}:{Uri.EscapeDataString(email)}?secret={user.TwoFactorSecretKey}&issuer={Uri.EscapeDataString(appName)}";

            // Tạo QR code dưới dạng base64 (luôn giống nhau cho cùng một secret key)
            var qrCodeBase64 = await GenerateQRCodeBase64(qrCodeUrl);

            return new TwoFactorQRDto
            {
                QrCodeBase64 = qrCodeBase64
            };
        }

        private async Task<string> GenerateQRCodeBase64(string content)
        {
            try
            {
                // Sử dụng QRCoder để tạo QR code với cài đặt cố định
                using var qrGenerator = new QRCoder.QRCodeGenerator();
                var qrCodeData = qrGenerator.CreateQrCode(content, QRCoder.QRCodeGenerator.ECCLevel.Q);
                using var qrCode = new QRCoder.PngByteQRCode(qrCodeData);
                // Sử dụng cài đặt cố định để đảm bảo QR code giống nhau cho cùng content
                var qrCodeBytes = qrCode.GetGraphic(20, new byte[] { 0, 0, 0 }, new byte[] { 255, 255, 255 });
                return await Task.FromResult($"data:image/png;base64,{Convert.ToBase64String(qrCodeBytes)}");
            }
            catch (Exception ex)
            {
                // Log error nếu cần
                Console.WriteLine($"Error generating QR code: {ex.Message}");

                // Fallback: return a simple 1x1 pixel placeholder
                var placeholderBytes = Convert.FromBase64String("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==");
                return $"data:image/png;base64,{Convert.ToBase64String(placeholderBytes)}";
            }
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
                new Claim("userId", user.Id),
                new Claim("email", user.Email ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Sub, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? string.Empty),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat,
                    new DateTimeOffset(DateTime.UtcNow).ToUnixTimeSeconds().ToString(),
                    ClaimValueTypes.Integer64)
            };

            // Thêm roles nếu có
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var jwtKey = _configuration["Jwt:Key"];
            if (string.IsNullOrEmpty(jwtKey))
                throw new InvalidOperationException("JWT Key not found in configuration");

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));

            var token = new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                expires: DateTime.UtcNow.AddHours(24),
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