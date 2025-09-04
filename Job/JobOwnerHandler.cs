using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using System.Threading.Tasks;

public class JobOwnerHandler : AuthorizationHandler<JobOwnerRequirement, Job>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        JobOwnerRequirement requirement,
        Job resource)
    {
        var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);

        if (resource.CreatedBy == userId)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
