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
                        Instructions = "Vui lòng sử dụng API verify-2fa với mã OTP"
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
        /// Xác minh mã 2FA khi đăng nhập (chỉ dành cho tài khoản đã bật 2FA)
        /// </summary>
        [HttpPost("verify-2fa")]
        [SwaggerOperation(Summary = "Xác minh mã 2FA khi đăng nhập")]
        [SwaggerResponse(200, "Xác minh thành công")]
        [SwaggerResponse(400, "Mã OTP không hợp lệ")]
        [SwaggerResponse(401, "Thông tin đăng nhập không đúng")]
        public async Task<IActionResult> Verify2FA([FromBody] Verify2FADto model)
        {
            try
            {
                var result = await _authService.Verify2FAAsync(model);

                return Ok(new
                {
                    Token = result.Token,
                    Message = result.Message
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
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
        /// Lấy mã QR để cấu hình 2FA trên ứng dụng Authenticator
        /// </summary>
        [Authorize]
        [HttpGet("get-2fa-qr")]
        [SwaggerOperation(Summary = "Lấy mã QR cấu hình 2FA")]
        [SwaggerResponse(200, "Mã QR để quét bằng ứng dụng Authenticator")]
        public async Task<IActionResult> Get2FAQRCode([FromQuery] bool returnBase64 = true)
        {
            try
            {
                var userId = GetCurrentUserId();
                var email = GetCurrentUserEmail();

                var qrCode = await _authService.Get2FAQRCodeAsync(userId, email);

                if (returnBase64)
                {
                    // Trả về JSON với base64
                    return Ok(new
                    {
                        QrCodeBase64 = qrCode.QrCodeBase64,
                        Instructions = new
                        {
                            Step1 = "Cài đặt app Google Authenticator, Microsoft Authenticator hoặc tương tự",
                            Step2 = "Quét mã QR code bên dưới bằng ứng dụng",
                            Step3 = "Nhập mã 6 số từ ứng dụng vào API toggle-2fa để bật/tắt 2FA"
                        }
                    });
                }
                else
                {
                    // Trả về trực tiếp file ảnh PNG
                    var base64Data = qrCode.QrCodeBase64.Replace("data:image/png;base64,", "");
                    var imageBytes = Convert.FromBase64String(base64Data);
                    return File(imageBytes, "image/png", "qr-code-2fa.png");
                }
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        /// <summary>
        /// Tự động bật/tắt 2FA dựa trên trạng thái hiện tại bằng mã OTP
        /// </summary>
        [Authorize]
        [HttpPost("toggle-2fa")]
        [SwaggerOperation(Summary = "Tự động bật hoặc tắt xác thực 2 yếu tố")]
        [SwaggerResponse(200, "Thao tác thành công")]
        [SwaggerResponse(400, "Mã OTP không hợp lệ")]
        public async Task<IActionResult> Toggle2FA([FromBody] Toggle2FADto model)
        {
            try
            {
                var userId = GetCurrentUserId();
                var result = await _authService.Toggle2FAAsync(userId, model.OtpCode);

                if (!result.Success)
                    return BadRequest(new { Message = result.Message });

                return Ok(new
                {
                    Message = result.Message,
                    Is2FAEnabled = result.IsEnabled,
                    Action = result.IsEnabled ? "Đã bật 2FA" : "Đã tắt 2FA",
                    Warning = !result.IsEnabled ? "Tài khoản của bạn ít an toàn hơn khi không sử dụng 2FA" : "Tài khoản của bạn giờ đây được bảo vệ tốt hơn với 2FA"
                });
            }
            catch (Exception ex)
            {
                return BadRequest(new { Message = ex.Message });
            }
        }

        /// <summary>
        /// Lấy thông tin profile người dùng (bao gồm trạng thái 2FA)
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