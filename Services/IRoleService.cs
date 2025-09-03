using Login.DTOs;
using System.Threading.Tasks;

public interface IRoleService
{
    Task<bool> AddRoleToUserAsync(RoleDto model);
    Task<bool> RemoveRoleFromUserAsync(RoleDto model);
    Task<IList<string>> GetUserRolesAsync(string userId);
}
