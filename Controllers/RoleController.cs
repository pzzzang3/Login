using Login.DTOs;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class RoleController : ControllerBase
{
    private readonly IRoleService _roleService;

    public RoleController(IRoleService roleService)
    {
        _roleService = roleService;
    }
    /// <summary>
    /// Gắn quyền cho người dùng (Admin mới có quyền này)
    /// </summary>
    [HttpPost("assign")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> AssignRole(RoleDto model)
    {
        var result = await _roleService.AddRoleToUserAsync(model);
        return result ? Ok("Đã thêm quyền thành công!") : BadRequest("Không thể thêm quyền!");
    }
    /// <summary>
    /// Xóa quyền của người dùng (Admin mới có quyền này)
    /// </summary>
    [HttpPost("remove")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> RemoveRole(RoleDto model)
    {
        var result = await _roleService.RemoveRoleFromUserAsync(model);
        return result ? Ok("Đã xóa quyền thành công!") : BadRequest("Không thể xóa quyền!");
    }
    /// <summary>
    /// Kiểm tra quyền của người dùng chỉ định
    /// </summary>
    [HttpGet("user/{userId}")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetUserRoles(string userId)
    {
        var roles = await _roleService.GetUserRolesAsync(userId);
        return Ok(roles);
    }
}
