using Login.Models.DTOs;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using OtpNet;
using System.Collections.Concurrent;
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
        private readonly IEmailSender _emailSender;

        // In-memory storage cho login sessions (có thể thay bằng Redis/Database trong production)
        private static readonly ConcurrentDictionary<string, LoginSession> _loginSessions = new();

        public AuthService(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IConfiguration configuration,
            IEmailSender emailSender)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
            _emailSender = emailSender;
        }

        public async Task<RegisterResponseDto> RegisterAsync(RegisterDto dto)
        {
            // Kiểm tra email đã tồn tại
            var existingUser = await _userManager.FindByEmailAsync(dto.Email);
            if (existingUser != null)
            {
                return new RegisterResponseDto
                {
                    Success = false,
                    Message = "Email đã được sử dụng bởi tài khoản khác"
                };
            }

            // Tạo user mới
            var user = new ApplicationUser
            {
                UserName = dto.Email,
                Email = dto.Email,
                TwoFactorEnabled = false,
                FirstName = dto.FullName?.Split(' ').FirstOrDefault(),
                LastName = dto.FullName?.Contains(' ') == true ?
                    string.Join(" ", dto.FullName.Split(' ').Skip(1)) : null,
                PhoneNumber = dto.PhoneNumber,
                EmailConfirmed = false // Chưa xác thực email
            };

            var result = await _userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return new RegisterResponseDto
                {
                    Success = false,
                    Message = $"Đăng ký thất bại: {errors}"
                };
            }

            // Tạo và gửi OTP qua email
            await GenerateAndSendEmailOtpAsync(user);

            return new RegisterResponseDto
            {
                Success = true,
                Message = "Đăng ký thành công! Vui lòng kiểm tra email để xác thực tài khoản."
            };
        }

        public async Task<VerifyEmailResponseDto> VerifyEmailAsync(VerifyEmailDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
            {
                return new VerifyEmailResponseDto
                {
                    Success = false,
                    Message = "Không tìm thấy tài khoản với email này"
                };
            }

            if (user.EmailConfirmed)
            {
                return new VerifyEmailResponseDto
                {
                    Success = false,
                    Message = "Email đã được xác thực trước đó"
                };
            }

            // Kiểm tra OTP
            if (string.IsNullOrEmpty(user.EmailOtpCode) ||
                user.EmailOtpExpiry == null ||
                user.EmailOtpExpiry < DateTime.UtcNow)
            {
                return new VerifyEmailResponseDto
                {
                    Success = false,
                    Message = "Mã OTP đã hết hạn. Vui lòng yêu cầu gửi lại mã mới."
                };
            }

            if (user.EmailOtpCode != dto.OtpCode)
            {
                return new VerifyEmailResponseDto
                {
                    Success = false,
                    Message = "Mã OTP không chính xác"
                };
            }

            // Xác thực thành công
            user.EmailConfirmed = true;
            user.EmailOtpCode = null;
            user.EmailOtpExpiry = null;
            await _userManager.UpdateAsync(user);

            return new VerifyEmailResponseDto
            {
                Success = true,
                Message = "Xác thực email thành công! Tài khoản đã được kích hoạt."
            };
        }

        public async Task<ResendEmailOtpResponseDto> ResendEmailOtpAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                return new ResendEmailOtpResponseDto
                {
                    Success = false,
                    Message = "Không tìm thấy tài khoản với email này"
                };
            }

            if (user.EmailConfirmed)
            {
                return new ResendEmailOtpResponseDto
                {
                    Success = false,
                    Message = "Email đã được xác thực, không cần gửi lại OTP"
                };
            }

            // Tạo và gửi OTP mới
            await GenerateAndSendEmailOtpAsync(user);

            return new ResendEmailOtpResponseDto
            {
                Success = true,
                Message = "Mã OTP mới đã được gửi đến email của bạn"
            };
        }

        public async Task<LoginResponseDto> LoginAsync(LoginDto dto)
        {
            var user = await _userManager.Users.FirstOrDefaultAsync(u => u.Email == dto.Email);
            if (user == null)
                throw new Exception("Email hoặc mật khẩu không đúng.");

            // Kiểm tra email đã được xác thực
            if (!user.EmailConfirmed)
                throw new Exception("Tài khoản chưa được kích hoạt. Vui lòng kiểm tra email để xác thực tài khoản.");

            // Kiểm tra mật khẩu
            var passwordValid = await _userManager.CheckPasswordAsync(user, dto.Password);
            if (!passwordValid)
                throw new Exception("Email hoặc mật khẩu không đúng.");

            // Nếu 2FA tắt → trả token luôn
            if (!user.TwoFactorEnabled)
            {
                // Cập nhật thời gian đăng nhập cuối
                user.LastLoginAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);

                var token = await GenerateJwtToken(user);
                return new LoginResponseDto
                {
                    Token = token,
                    RequiresTwoFactor = false,
                    Message = "Đăng nhập thành công"
                };
            }

            // Nếu 2FA bật → tạo login session
            var sessionId = Guid.NewGuid().ToString();
            var loginSession = new LoginSession
            {
                SessionId = sessionId,
                UserId = user.Id,
                Email = user.Email!,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(5), // Session có hiệu lực 5 phút
                RememberMe = dto.RememberMe
            };

            _loginSessions[sessionId] = loginSession;

            return new LoginResponseDto
            {
                RequiresTwoFactor = true,
                LoginSessionId = sessionId,
                Message = "Tài khoản đang bật 2FA. Vui lòng nhập OTP vào API confirm-login để hoàn tất đăng nhập."
            };
        }

        public async Task<ConfirmLoginResponseDto> ConfirmLoginAsync(ConfirmLoginDto dto)
        {
            // Kiểm tra session
            if (!_loginSessions.TryGetValue(dto.LoginSessionId, out var session))
            {
                return new ConfirmLoginResponseDto
                {
                    Success = false,
                    Message = "Session không hợp lệ hoặc đã hết hạn"
                };
            }

            if (session.ExpiresAt < DateTime.UtcNow)
            {
                _loginSessions.TryRemove(dto.LoginSessionId, out _);
                return new ConfirmLoginResponseDto
                {
                    Success = false,
                    Message = "Session đã hết hạn. Vui lòng đăng nhập lại."
                };
            }

            var user = await _userManager.FindByIdAsync(session.UserId);
            if (user == null)
            {
                _loginSessions.TryRemove(dto.LoginSessionId, out _);
                return new ConfirmLoginResponseDto
                {
                    Success = false,
                    Message = "Người dùng không tồn tại"
                };
            }

            // Xác thực mã OTP
            if (!VerifyOtp(user.TwoFactorSecretKey, dto.OtpCode))
            {
                return new ConfirmLoginResponseDto
                {
                    Success = false,
                    Message = "Mã OTP không hợp lệ"
                };
            }

            // Xóa session sau khi xác thực thành công
            _loginSessions.TryRemove(dto.LoginSessionId, out _);

            // Cập nhật thời gian đăng nhập cuối
            user.LastLoginAt = DateTime.UtcNow;
            await _userManager.UpdateAsync(user);

            // Tạo JWT token
            var token = await GenerateJwtToken(user);
            return new ConfirmLoginResponseDto
            {
                Success = true,
                Token = token,
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

        public async Task<bool> LogoutAsync(string userId)
        {
            // Xóa tất cả login sessions của user này
            var sessionsToRemove = _loginSessions.Where(kvp => kvp.Value.UserId == userId).ToList();
            foreach (var session in sessionsToRemove)
            {
                _loginSessions.TryRemove(session.Key, out _);
            }

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
        private async Task GenerateAndSendEmailOtpAsync(ApplicationUser user)
        {
            // Tạo mã OTP 6 số
            var random = new Random();
            var otpCode = random.Next(100000, 999999).ToString();

            // Lưu OTP vào database với thời gian hết hạn 10 phút
            user.EmailOtpCode = otpCode;
            user.EmailOtpExpiry = DateTime.UtcNow.AddMinutes(10);
            await _userManager.UpdateAsync(user);

            // Gửi email
            var subject = "Xác thực tài khoản - Auth2FA App";
            var body = $@"
                <h2>Xác thực tài khoản</h2>
                <p>Chào {user.FirstName ?? user.Email},</p>
                <p>Mã OTP để xác thực tài khoản của bạn là:</p>
                <h3 style='color: #007bff; font-size: 24px; letter-spacing: 2px;'>{otpCode}</h3>
                <p><strong>Lưu ý:</strong> Mã này sẽ hết hạn sau 10 phút.</p>
                <p>Nếu bạn không tạo tài khoản này, vui lòng bỏ qua email này.</p>
                <br/>
                <p>Trân trọng,<br/>Auth2FA App Team</p>
            ";

            try
            {
                await _emailSender.SendEmailAsync(user.Email!, subject, body);
            }
            catch (Exception ex)
            {
                // Log error nhưng không throw để không làm gián đoạn quá trình đăng ký
                Console.WriteLine($"Error sending email: {ex.Message}");
                // Trong production, có thể log vào file hoặc monitoring system
            }
        }

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

        // Background task để dọn dẹp expired sessions (có thể chạy riêng trong production)
        public static void CleanupExpiredSessions()
        {
            var expiredSessions = _loginSessions.Where(kvp => kvp.Value.ExpiresAt < DateTime.UtcNow).ToList();
            foreach (var session in expiredSessions)
            {
                _loginSessions.TryRemove(session.Key, out _);
            }
        }
    }
}