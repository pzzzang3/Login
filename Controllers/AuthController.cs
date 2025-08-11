using Login.Models.DTOs;
using Login.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Swashbuckle.AspNetCore.Annotations;
using System.Security.Claims;

namespace Login.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        /// <summary>
        /// Đăng ký tài khoản mới (mặc định chưa bật 2FA)
        /// </summary>
        [HttpPost("register")]
        [SwaggerOperation(Summary = "Đăng ký tài khoản mới")]
        [SwaggerResponse(200, "Đăng ký thành công, vui lòng đăng nhập")]
        [SwaggerResponse(400, "Đăng ký thất bại")]
        public async Task<IActionResult> Register([FromBody] RegisterDto model)
        {
            try
            {
                var result = await _authService.RegisterAsync(model);
                if (!result)
                    return BadRequest("Đăng ký thất bại");

                return Ok(new
                {
                    Message = "Đăng ký thành công! Vui lòng đăng nhập để tiếp tục.",
                    RequiresLogin = true
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        /// <summary>
        /// Đăng nhập (trả token nếu chưa bật 2FA, yêu cầu OTP nếu đã bật 2FA)
        /// </summary>
        [HttpPost("login")]
        [SwaggerOperation(Summary = "Đăng nhập vào hệ thống")]
        [SwaggerResponse(200, "Đăng nhập thành công hoặc yêu cầu 2FA")]
        [SwaggerResponse(401, "Thông tin đăng nhập không đúng")]
        public async Task<IActionResult> Login([FromBody] LoginDto model)
        {
            try
            {
                var result = await _authService.LoginAsync(model);

                if (result.RequiresTwoFactor)
                {
                    return Ok(new
                    {
                        Message = result.Message,
                        RequiresTwoFactor = true,
                        Instructions = "Vui lòng gửi lại request với TwoFactorCode"
                    });
                }

                return Ok(new
                {
                    Token = result.Token,
                    Message = result.Message
                });
            }
            catch (Exception ex)
            {
                return Unauthorized(new { Message = ex.Message });
            }
        }

        /// <summary>
        /// Đăng xuất (invalidate token - hiện tại chỉ symbolic vì JWT stateless)
        /// </summary>
        [Authorize]
        [HttpPost("logout")]
        [SwaggerOperation(Summary = "Đăng xuất khỏi hệ thống")]
        [SwaggerResponse(200, "Đăng xuất thành công")]
        public async Task<IActionResult> Logout()
        {
            try
            {
                var userId = GetCurrentUserId();
                await _authService.LogoutAsync(userId);

                return Ok(new
                {
                    Message = "Đăng xuất thành công. Vui lòng xóa token ở phía client."
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        /// <summary>
        /// Lấy thông tin cấu hình 2FA (QR code và secret key)
        /// </summary>
        [Authorize]
        [HttpGet("get-2fa-setup")]
        [SwaggerOperation(Summary = "Lấy thông tin cấu hình 2FA")]
        [SwaggerResponse(200, "Thông tin cấu hình 2FA")]
        public async Task<IActionResult> Get2FASetup()
        {
            try
            {
                var userId = GetCurrentUserId();
                var email = GetCurrentUserEmail();

                var setupInfo = await _authService.Get2FASetupAsync(userId, email);
                return Ok(new
                {
                    SecretKey = setupInfo.SecretKey,
                    QrCodeUrl = setupInfo.QrCodeUrl,
                    ManualEntryKey = setupInfo.ManualEntryKey,
                    Instructions = new
                    {
                        Step1 = "Cài đặt app Google Authenticator hoặc tương tự",
                        Step2 = "Quét QR code hoặc nhập manual key",
                        Step3 = "Nhập mã 6 số để bật 2FA"
                    }
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        /// <summary>
        /// Bật 2FA với mã OTP từ Google Authenticator
        /// </summary>
        [Authorize]
        [HttpPost("enable-2fa")]
        [SwaggerOperation(Summary = "Bật xác thực 2 yếu tố")]
        [SwaggerResponse(200, "Bật 2FA thành công")]
        [SwaggerResponse(400, "Mã OTP không hợp lệ")]
        public async Task<IActionResult> Enable2FA([FromBody] Enable2FADto model)
        {
            try
            {
                var userId = GetCurrentUserId();
                var result = await _authService.Enable2FAAsync(userId, model.OtpCode);

                if (!result)
                    return BadRequest(new { Message = "Mã OTP không hợp lệ hoặc đã hết hạn" });

                return Ok(new
                {
                    Message = "Đã bật 2FA thành công! Tài khoản của bạn giờ đây an toàn hơn.",
                    Is2FAEnabled = true
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        /// <summary>
        /// Tắt 2FA với mã OTP xác nhận
        /// </summary>
        [Authorize]
        [HttpPost("disable-2fa")]
        [SwaggerOperation(Summary = "Tắt xác thực 2 yếu tố")]
        [SwaggerResponse(200, "Tắt 2FA thành công")]
        [SwaggerResponse(400, "Mã OTP không hợp lệ")]
        public async Task<IActionResult> Disable2FA([FromBody] Disable2FADto model)
        {
            try
            {
                var userId = GetCurrentUserId();
                var result = await _authService.Disable2FAAsync(userId, model.OtpCode);

                if (!result)
                    return BadRequest(new { Message = "Mã OTP không hợp lệ" });

                return Ok(new
                {
                    Message = "Đã tắt 2FA thành công.",
                    Is2FAEnabled = false,
                    Warning = "Tài khoản của bạn ít an toàn hơn khi không sử dụng 2FA"
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        /// <summary>
        /// Kiểm tra trạng thái 2FA của tài khoản
        /// </summary>
        [Authorize]
        [HttpGet("2fa-status")]
        [SwaggerOperation(Summary = "Kiểm tra trạng thái 2FA")]
        [SwaggerResponse(200, "Trạng thái 2FA")]
        public async Task<IActionResult> Get2FAStatus()
        {
            try
            {
                var userId = GetCurrentUserId();
                var isEnabled = await _authService.Is2FAEnabledAsync(userId);

                return Ok(new
                {
                    Is2FAEnabled = isEnabled,
                    Status = isEnabled ? "Đã bật 2FA" : "Chưa bật 2FA",
                    Recommendation = isEnabled ?
                        "Tài khoản của bạn được bảo vệ bởi 2FA" :
                        "Khuyến nghị bật 2FA để tăng cường bảo mật"
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        /// <summary>
        /// Lấy thông tin profile người dùng
        /// </summary>
        [Authorize]
        [HttpGet("profile")]
        [SwaggerOperation(Summary = "Lấy thông tin profile người dùng")]
        [SwaggerResponse(200, "Thông tin profile")]
        public async Task<IActionResult> GetProfile()
        {
            try
            {
                var userId = GetCurrentUserId();
                var profile = await _authService.GetUserProfileAsync(userId);

                return Ok(profile);
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        /// <summary>
        /// Xác minh OTP email (nếu cần thiết)
        /// </summary>
        [HttpPost("verify-email-otp")]
        [SwaggerOperation(Summary = "Xác minh email OTP")]
        [SwaggerResponse(200, "Xác minh email thành công")]
        [SwaggerResponse(400, "Token không hợp lệ")]
        public async Task<IActionResult> VerifyEmailOtp([FromQuery] string email, [FromQuery] string token)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token))
                return BadRequest(new { Message = "Email và token là bắt buộc." });

            try
            {
                var result = await _authService.VerifyEmailOtpAsync(email, token);
                if (!result)
                    return BadRequest(new { Message = "Token không hợp lệ hoặc đã hết hạn" });

                return Ok(new { Message = "Xác minh email thành công" });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        // Helper methods
        private string GetCurrentUserId()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                throw new UnauthorizedAccessException("Không thể xác định người dùng");
            return userId;
        }

        private string GetCurrentUserEmail()
        {
            var email = User.FindFirst(ClaimTypes.Email)?.Value;
            if (string.IsNullOrEmpty(email))
                throw new UnauthorizedAccessException("Không thể xác định email người dùng");
            return email;
        }
    }
}