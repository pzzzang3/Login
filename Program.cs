using Login.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.SwaggerGen;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// === 1. Add DbContext ===
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// === 2. Add Identity ===
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password requirements
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 6;
    options.Password.RequiredUniqueChars = 1;

    // User requirements
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = true; // Bật yêu cầu xác thực email
    options.SignIn.RequireConfirmedPhoneNumber = false;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;

    // Two Factor settings
    options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
})
.AddEntityFrameworkStores<AppDbContext>()
.AddDefaultTokenProviders();

// === 3. Add JWT Authentication ===
var jwtKey = builder.Configuration["Jwt:Key"];
var jwtIssuer = builder.Configuration["Jwt:Issuer"];
var jwtAudience = builder.Configuration["Jwt:Audience"];

if (string.IsNullOrEmpty(jwtKey))
{
    throw new InvalidOperationException("JWT Key not found in configuration");
}

Console.WriteLine($"JWT Config - Issuer: {jwtIssuer}, Audience: {jwtAudience}");

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = false; // Tạm tắt cho development
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtIssuer,
        ValidAudience = jwtAudience,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        ClockSkew = TimeSpan.Zero, // Remove delay of token when expire
        RequireExpirationTime = true,
        // Validate claims
        NameClaimType = ClaimTypes.NameIdentifier,
        RoleClaimType = ClaimTypes.Role
    };

    // Add event handlers for debugging
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            Console.WriteLine($"JWT Authentication failed: {context.Exception.Message}");
            if (context.Exception is SecurityTokenExpiredException)
            {
                context.Response.Headers.Add("Token-Expired", "true");
            }
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            var userId = context.Principal?.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var email = context.Principal?.FindFirst(ClaimTypes.Email)?.Value;
            Console.WriteLine($"JWT Token validated - UserId: {userId}, Email: {email}");
            return Task.CompletedTask;
        },
        OnChallenge = context =>
        {
            Console.WriteLine($"JWT Challenge: {context.Error}, {context.ErrorDescription}");
            return Task.CompletedTask;
        },
        OnMessageReceived = context =>
        {
            var token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            if (!string.IsNullOrEmpty(token))
            {
                Console.WriteLine($"JWT Token received: {token[..Math.Min(50, token.Length)]}...");
            }
            return Task.CompletedTask;
        }
    };
});

// === 4. Add Authorization ===
builder.Services.AddAuthorization(options =>
{
    // Policy: chỉ HR mới được dùng
    options.AddPolicy("RequireHR", policy =>
        policy.RequireRole("HR"));

    // Policy: user phải có email xác thực
    options.AddPolicy("EmailVerified", policy =>
        policy.RequireClaim("EmailConfirmed", "True"));
});


builder.Services.AddScoped<IRoleService, RoleService>();

// === 5. Add CORS (if needed for frontend) ===
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
    });
});

// === 6. Add Dependency Injection for Services ===
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddSingleton<IAuthorizationHandler, JobOwnerHandler>();

// Add EmailSender - Use Mock in Development if email settings are not configured
var emailHost = builder.Configuration["EmailSettings:Host"];
var emailUsername = builder.Configuration["EmailSettings:Username"];
var emailPassword = builder.Configuration["EmailSettings:Password"];

if (builder.Environment.IsDevelopment() &&
    (string.IsNullOrEmpty(emailHost) || string.IsNullOrEmpty(emailUsername) || string.IsNullOrEmpty(emailPassword)))
{
    builder.Services.AddTransient<IEmailSender>(provider =>
        new Login.Services.MockEmailSender(provider.GetService<ILogger<Login.Services.MockEmailSender>>()!));
    Console.WriteLine("⚠️  Using MockEmailSender - Email settings not configured");
}
else
{
    builder.Services.AddTransient<IEmailSender>(provider =>
        new Login.Services.EmailSender(
            provider.GetService<IConfiguration>()!,
            provider.GetService<ILogger<Login.Services.EmailSender>>()!));
    Console.WriteLine("✅ Using real EmailSender with SMTP configuration");
}

// === 7. Add Controllers + API Explorer ===
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// === 8. Add Swagger with Enhanced Documentation ===
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Version = "v1",
        Title = "Authentication 2FA API with Email Verification",
        Contact = new OpenApiContact
        {
            Name = "Development Team",
            Email = "dev@company.com"
        }
    });

    // Enable annotations
    options.EnableAnnotations();

    // Add JWT Authentication to Swagger
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = @"**Cách sử dụng JWT Token:**
1. Đăng nhập để lấy token từ response
2. Copy token (bỏ qua 'Bearer ' nếu có)  
3. Paste vào ô bên dưới
4. Nhấn 'Authorize' 

**Ví dụ token:** eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });

    // Include XML comments if available
    var xmlFile = $"{System.Reflection.Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    if (File.Exists(xmlPath))
    {
        options.IncludeXmlComments(xmlPath);
    }
});

// === 9. Add Background Service for session cleanup (optional) ===
builder.Services.AddHostedService<SessionCleanupService>();

var app = builder.Build();

// Seed role khi chạy lần đầu
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    await DataSeeder.SeedRolesAsync(roleManager);
}
// === Configure Pipeline ===
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Auth 2FA API V1 - Email Verification");
        c.RoutePrefix = string.Empty; // Mở Swagger UI tại "/"
        c.DocExpansion(Swashbuckle.AspNetCore.SwaggerUI.DocExpansion.List);
        c.DefaultModelRendering(Swashbuckle.AspNetCore.SwaggerUI.ModelRendering.Model);
        c.EnableDeepLinking();
        c.ShowExtensions();
    });
}

app.UseHttpsRedirection();
app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// Display startup info
Console.WriteLine("=== Auth 2FA API with Email Verification Started ===");
Console.WriteLine($"Environment: {app.Environment.EnvironmentName}");
Console.WriteLine($"Swagger UI: {(app.Environment.IsDevelopment() ? "http://localhost:5128" : "Disabled in production")}");
Console.WriteLine("Features:");
Console.WriteLine("- Email verification with OTP");
Console.WriteLine("- 2FA with Google Authenticator");
Console.WriteLine("- JWT Authentication");
Console.WriteLine("- Secure login flow");
Console.WriteLine("==============================================");

app.Run();

// Background service để dọn dẹp expired sessions
public class SessionCleanupService : BackgroundService
{
    private readonly ILogger<SessionCleanupService> _logger;

    public SessionCleanupService(ILogger<SessionCleanupService> logger)
    {
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                AuthService.CleanupExpiredSessions();
                _logger.LogInformation("Cleaned up expired login sessions at {Time}", DateTimeOffset.Now);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during session cleanup");
            }

            // Chạy mỗi 5 phút
            await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
        }
    }
}