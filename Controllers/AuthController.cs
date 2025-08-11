using Login.Models.DTOs;    // namespace chứa RegisterDto, LoginDto
using Login.Services;   // namespace chứa IAuthService
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
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

        // 1. Đăng ký
        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDto model)
        {
            try
            {
                var result = await _authService.RegisterAsync(model);
                if (!result)
                    return BadRequest("Đăng ký thất bại");

                return Ok("Đăng ký thành công");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        // 2. Xác minh OTP email
        [HttpPost("verify-email-otp")]
        public async Task<IActionResult> VerifyEmailOtp([FromQuery] string email, [FromQuery] string token)
        {
            if (string.IsNullOrEmpty(email) || string.IsNullOrEmpty(token))
                return BadRequest("Email và token là bắt buộc.");

            try
            {
                var result = await _authService.VerifyEmailOtpAsync(email, token);
                if (!result)
                    return BadRequest("Token không hợp lệ hoặc đã hết hạn");

                return Ok("Xác minh email thành công");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        // 3. Đăng nhập (có hỗ trợ 2FA)
        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDto model)
        {
            try
            {
                var token = await _authService.LoginAsync(model);
                return Ok(new { Token = token });
            }
            catch (Exception ex)
            {
                return Unauthorized(ex.Message);
            }
        }

        // 4. Bật 2FA
        [Authorize]
        [HttpPost("enable-2fa")]
        public async Task<IActionResult> EnableTwoFactor([FromBody] Enable2FADto model)
        {
            try
            {
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                    return Unauthorized("Không thể xác định người dùng");

                var result = await _authService.Enable2FAAsync(userId, model.OtpCode);
                return result ? Ok("Đã bật 2FA thành công") : BadRequest("Mã OTP không hợp lệ");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        // 5. Tắt 2FA
        [Authorize]
        [HttpPost("disable-2fa")]
        public async Task<IActionResult> DisableTwoFactor([FromBody] Disable2FADto model)
        {
            try
            {
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                    return Unauthorized("Không thể xác định người dùng");

                var result = await _authService.Disable2FAAsync(userId, model.OtpCode);
                return result ? Ok("Đã tắt 2FA thành công") : BadRequest("Mã OTP không hợp lệ");
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        // 6. Kiểm tra trạng thái 2FA
        [Authorize]
        [HttpGet("is-2fa-enabled")]
        public async Task<IActionResult> IsTwoFactorEnabled()
        {
            try
            {
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                    return Unauthorized("Không thể xác định người dùng");

                var result = await _authService.Is2FAEnabledAsync(userId);
                return Ok(new { Enabled = result });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        // 7. Lấy secret key cho việc cấu hình Google Authenticator
        [Authorize]
        [HttpGet("get-2fa-setup")]
        public async Task<IActionResult> Get2FASetup()
        {
            try
            {
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                var email = User.FindFirst(ClaimTypes.Email)?.Value;

                if (string.IsNullOrEmpty(userId))
                    return Unauthorized("Không thể xác định người dùng");

                var setupInfo = await _authService.Get2FASetupAsync(userId, email);
                return Ok(setupInfo);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}