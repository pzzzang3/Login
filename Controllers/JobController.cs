using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class JobController : ControllerBase
{
    // Chỉ HR mới được tạo job
    [HttpPost("create")]
    [Authorize(Policy = "RequireHR")]
    public IActionResult CreateJob([FromBody] string title)
    {
        return Ok($"Job '{title}' created successfully!");
    }

    // Chỉ user có email xác minh mới được apply job
    [HttpPost("apply")]
    [Authorize(Policy = "EmailVerified")]
    public IActionResult ApplyJob([FromBody] string jobId)
    {
        return Ok($"Applied to job {jobId} successfully!");
    }
    [HttpPut("update/{id}")]
    public async Task<IActionResult> UpdateJob(string id, [FromBody] string newTitle,
    [FromServices] IAuthorizationService authorizationService)
    {
        // giả lập job từ DB
        var job = new Job { Id = id, Title = "Old Title", CreatedBy = "123" };

        var authResult = await authorizationService.AuthorizeAsync(User, job, new JobOwnerRequirement());
        if (!authResult.Succeeded)
        {
            return Forbid();
        }

        job.Title = newTitle;
        return Ok($"Job {id} updated successfully to {newTitle}");
    }

}
