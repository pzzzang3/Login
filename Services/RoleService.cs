using Login.DTOs;
using Microsoft.AspNetCore.Identity;


public class RoleService : IRoleService
{
    private readonly UserManager<ApplicationUser> _userManager;

    public RoleService(UserManager<ApplicationUser> userManager)
    {
        _userManager = userManager;
    }

    public async Task<bool> AddRoleToUserAsync(RoleDto model)
    {
        var user = await _userManager.FindByIdAsync(model.UserId);
        if (user == null) return false;

        var result = await _userManager.AddToRoleAsync(user, model.Role);
        return result.Succeeded;
    }

    public async Task<bool> RemoveRoleFromUserAsync(RoleDto model)
    {
        var user = await _userManager.FindByIdAsync(model.UserId);
        if (user == null) return false;

        var result = await _userManager.RemoveFromRoleAsync(user, model.Role);
        return result.Succeeded;
    }

    public async Task<IList<string>> GetUserRolesAsync(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        return user != null ? await _userManager.GetRolesAsync(user) : new List<string>();
    }
}
