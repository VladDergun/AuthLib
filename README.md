# AuthLib

A modern, flexible authentication library for .NET 10.0 with JWT tokens, refresh token rotation, role-based authorization, and Entity Framework Core integration.

[![NuGet](https://img.shields.io/nuget/v/VladyslavDerhun.AuthLib.svg)](https://www.nuget.org/packages/VladyslavDerhun.AuthLib/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **JWT Authentication** - Secure token-based authentication with access and refresh tokens
- **ASP.NET Core Integration** - Built-in support for `[Authorize]` attribute and JWT middleware
- **Two-Factor Authentication (2FA)** - TOTP-based 2FA with QR code generation
- **Token Rotation** - Automatic refresh token rotation for enhanced security
- **Role-Based Authorization** - Flexible role management with default role assignment
- **Email Verification** - Optional email verification workflow
- **Password Reset** - Secure password reset with time-limited tokens
- **Multi-Device Support** - Logout from current device or all devices
- **Automatic Token Cleanup** - Background service to clean up expired tokens
- **Entity Framework Core Integration** - Seamless integration with EF Core
- **Customizable Models** - Extend user and role models with your own properties
- **Flexible Key Types** - Support for `string`, `int`, `Guid`, and other key types
- **Password Validation** - Configurable password complexity requirements

## Installation

Install via NuGet Package Manager:

```bash
dotnet add package VladyslavDerhun.AuthLib
```

Or via Package Manager Console:

```powershell
Install-Package VladyslavDerhun.AuthLib
```

## Quick Start

### 1. Define Your Models

```csharp
using AuthLib.Models;

public class User : AuthUser<int, Role>
{
    public string Username { get; set; } = string.Empty;
    // Add your custom properties here
}

public class Role : AuthRole<int>
{
    // Add your custom properties here
}
```

### 2. Create Your DbContext

```csharp
using AuthLib.Contexts;
using Microsoft.EntityFrameworkCore;

public class AppDbContext : AuthDbContext<int, User, Role>
{
    public AppDbContext(DbContextOptions options) : base(options)
    {
    }
}
```

### 3. Configure Services

```csharp
using AuthLib.DependencyInjection;
using AuthLib.Options;

var builder = WebApplication.CreateBuilder(args);

// Add DbContext
builder.Services.AddDbContext<AppDbContext>(options =>
{
    options.UseNpgsql(builder.Configuration.GetConnectionString("Default"));
});

// Configure AuthLib
builder.Services.AddAuthServices(new AuthOptions
{
    PasswordSecret = "your-password-secret",
    TokenSecret = "your-token-secret",
    EmailVerificationRequired = false,
    Roles = new List<Role>
    {
        new() { Name = "User", IsDefault = true },
        new() { Name = "Admin", IsDefault = false }
    },
    JWTOptions = new JWTOptions
    {
        Issuer = "YourApp",
        Audience = "YourAppUsers",
        SigningKey = "your-signing-key-at-least-32-characters-long",
        AccessTokenLifetime = TimeSpan.FromMinutes(15),
        RefreshTokenLifetime = TimeSpan.FromDays(7)
    },
    PasswordOptions = new PasswordOptions
    {
        RequireMinLength = 8,
        RequireDigitCount = 1,
        RequireUppercaseCount = 1,
        RequireLowercaseCount = 1
    },
    TokenCleanupOptions = new TokenCleanupOptions
    {
        Enabled = true,
        CleanupInterval = TimeSpan.FromHours(24),
        RetentionPeriod = TimeSpan.FromDays(30)
    }
})
.AddEntityFrameworkStores<AppDbContext>()
.AddJwtAuthentication(); // Enable JWT authentication for [Authorize] attribute

var app = builder.Build();

// Add authentication & authorization middleware
app.UseAuthentication();
app.UseAuthorization();

// Rest of the code remains the same
using AuthLib.Interfaces.Services;
using AuthLib.Common.Dtos;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto)
    {
        var result = await _authService.RegisterAsync(dto.Email, dto.Password);
        
        if (!result.IsSuccess)
            return BadRequest(result.ErrorCode);
            
        return Ok(result.Value);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto dto)
    {
        var result = await _authService.LoginAsync(dto.Email, dto.Password);
        
        if (!result.IsSuccess)
            return BadRequest(result.ErrorCode);
            
        return Ok(result.Value);
    }

    [HttpPost("refresh")]
    public async Task<IActionResult> Refresh([FromBody] RefreshDto dto)
    {
        var result = await _authService.RefreshAsync(dto.RefreshToken);
        
        if (!result.IsSuccess)
            return BadRequest(result.ErrorCode);
            
        return Ok(result.Value);
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout([FromBody] LogoutDto dto)
    {
        var result = await _authService.LogoutAsync(dto.RefreshToken);
        
        if (!result.IsSuccess)
            return BadRequest(result.ErrorCode);
            
        return Ok();
    }
}

### 5. Protect Endpoints with [Authorize]

```csharp
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class ProfileController : ControllerBase
{
    [HttpGet]
    [Authorize] // Requires valid JWT token
    public IActionResult GetProfile()
    {
        var userId = User.FindFirst("sub")?.Value; // Get user ID from token
        var email = User.FindFirst("email")?.Value; // Get email from token
        var roles = User.FindAll("role").Select(c => c.Value); // Get roles from token
        
        return Ok(new { userId, email, roles });
    }
    
    [HttpGet("admin")]
    [Authorize(Roles = "Admin")] // Requires Admin role
    public IActionResult AdminOnly()
    {
        return Ok("Admin access granted");
    }
}

## API Reference

### IAuthService

The main service interface for authentication operations.

#### Methods

- **`LoginAsync(email, password)`** - Authenticate user and return tokens
- **`RegisterAsync(email, password)`** - Register new user with default role
- **`RegisterAsync(email, password, roleName)`** - Register new user with specific role
- **`RefreshAsync(refreshToken)`** - Refresh access token using refresh token
- **`LogoutAsync(refreshToken)`** - Logout from current device
- **`LogoutAllAsync(refreshToken)`** - Logout from all devices
- **`RequestPasswordResetAsync(email)`** - Generate password reset token
- **`ResetPasswordAsync(token, newPassword)`** - Reset password using token
- **`VerifyEmailAsync(token)`** - Verify user email address

### IAuthService\<TUser\>

Extended interface for custom user models.

#### Methods

- **`RegisterAsync(user, password)`** - Register with custom user object
- **`RegisterAsync(user, password, roleName)`** - Register with custom user object and role

## Configuration Options

### AuthOptions

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `PasswordSecret` | `string` | Yes | Secret for password hashing |
| `TokenSecret` | `string` | Yes | Secret for token generation |
| `EmailVerificationRequired` | `bool` | No | Require email verification (default: `false`) |
| `Roles` | `List<Role>` | Yes | Available roles in the system |
| `JWTOptions` | `JWTOptions` | Yes | JWT configuration |
| `PasswordOptions` | `PasswordOptions` | No | Password validation rules |
| `TokenCleanupOptions` | `TokenCleanupOptions` | No | Token cleanup configuration |

### JWTOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Issuer` | `string` | Required | JWT issuer claim |
| `Audience` | `string` | Required | JWT audience claim |
| `SigningKey` | `string` | Required | Key for signing tokens |
| `AccessTokenLifetime` | `TimeSpan` | 15 minutes | Access token expiration |
| `RefreshTokenLifetime` | `TimeSpan` | 7 days | Refresh token expiration |
| `EmailVerificationTokenLifetime` | `TimeSpan` | 1 day | Email verification token expiration |
| `PasswordResetTokenLifetime` | `TimeSpan` | 30 minutes | Password reset token expiration |

### PasswordOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `RequireMinLength` | `int` | 6 | Minimum password length |
| `RequireMaxLength` | `int` | 100 | Maximum password length |
| `RequireDigitCount` | `int` | 0 | Minimum number of digits |
| `RequireLowercaseCount` | `int` | 0 | Minimum lowercase characters |
| `RequireUppercaseCount` | `int` | 0 | Minimum uppercase characters |
| `RequireNonAlphanumericCount` | `int` | 0 | Minimum special characters |
| `RequireRegexValidation` | `Regex?` | null | Custom regex validation |
| `AllowedSpecialSymbols` | `char[]?` | null | Allowed special characters |

### TokenCleanupOptions

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `Enabled` | `bool` | true | Enable automatic cleanup |
| `CleanupInterval` | `TimeSpan` | 24 hours | Cleanup frequency |
| `RetentionPeriod` | `TimeSpan` | 30 days | How long to keep expired tokens |

## Advanced Usage

### Custom User Model with Additional Properties

```csharp
public class User : AuthUser<int, Role>
{
    public string Username { get; set; } = string.Empty;
    public string FirstName { get; set; } = string.Empty;
    public string LastName { get; set; } = string.Empty;
    public DateTime? DateOfBirth { get; set; }
}

// Register with custom user
var user = new User
{
    Email = "user@example.com",
    Username = "johndoe",
    FirstName = "John",
    LastName = "Doe"
};

var result = await authService.RegisterAsync(user, "password123");
```

### Email Verification Flow

```csharp
// 1. Enable email verification in options
EmailVerificationRequired = true

// 2. After registration, send verification email
var result = await authService.RegisterAsync(email, password);
// Send result.Value.EmailVerificationToken via email to user

// 3. User clicks link with token
var verifyResult = await authService.VerifyEmailAsync(token);
```

### Password Reset Flow

```csharp
// 1. User requests password reset
var result = await authService.RequestPasswordResetAsync(email);
// Send result.Value (reset token) via email to user

// 2. User submits new password with token
var resetResult = await authService.ResetPasswordAsync(token, newPassword);
```

### Using Different Key Types

```csharp
// With Guid keys
public class User : AuthUser<Guid, Role> { }
public class Role : AuthRole<Guid> { }
public class AppDbContext : AuthDbContext<Guid, User, Role> { }

// With string keys (default)
public class User : AuthUser<Role> { }
public class Role : AuthRole { }
public class AppDbContext : AuthDbContext<User> { }
```

## Security Best Practices

1. **Store secrets securely** - Use environment variables or Azure Key Vault for production
2. **Use strong signing keys** - Minimum 32 characters for JWT signing key
3. **Enable HTTPS** - Always use HTTPS in production
4. **Implement rate limiting** - Protect login/register endpoints from brute force
5. **Token rotation** - The library automatically rotates refresh tokens on each refresh
6. **Revocation detection** - Reusing a revoked token will revoke all user tokens

## Error Handling

All methods return a `Result<T>` or `Result` object with the following properties:

```csharp
var result = await authService.LoginAsync(email, password);

if (result.IsSuccess)
{
    var tokens = result.Value;
    // Use tokens.AccessToken and tokens.RefreshToken
}
else
{
    // Handle error using result.ErrorCode
    switch (result.ErrorCode)
    {
        case AuthErrorCode.InvalidCredentials:
            return Unauthorized("Invalid email or password");
        case AuthErrorCode.EmailNotVerified:
            return Unauthorized("Please verify your email");
        // ... handle other error codes
    }
}
```

## Database Migrations

Don't forget to create and apply migrations:

```bash
dotnet ef migrations add InitialCreate
dotnet ef database update
```

## Requirements

- .NET 10.0 or later
- Entity Framework Core 10.0.5 or later
- A supported database provider (SQL Server, PostgreSQL, MySQL, etc.)

## Dependencies

- `BCrypt.Net-Next` (4.1.0) - Password hashing
- `Microsoft.EntityFrameworkCore` (10.0.5) - Data access
- `System.IdentityModel.Tokens.Jwt` (8.17.0) - JWT token handling

## License

This project is licensed under the MIT License - see the [LICENSE.txt](LICENSE.txt) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Author

**Vladyslav Derhun**

## Repository

[https://github.com/VladDergun/AuthLib](https://github.com/VladDergun/AuthLib)