using System.Collections.Concurrent;
using System.Net.Mail;
using System.Text.Json;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.OpenApi.Models;


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "User Management API",
        Version = "v1",
        Description = "TechHive Solutions - User Management API"
    });

    // Add Bearer auth to Swagger
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "API token authentication.\nEnter ONLY your token value (Swagger will add 'Bearer ' automatically).",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
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
});


var app = builder.Build();

// === Middleware pipeline (order required by activity) ===
// 1) Error handling
app.UseSimpleErrorHandler();
// 2) Authentication
app.UseTokenAuth();
// 3) Logging (last)
app.UseRequestResponseLogging();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// In-memory stores
var users = new ConcurrentDictionary<Guid, User>();
var emailIndex = new ConcurrentDictionary<string, Guid>(StringComparer.OrdinalIgnoreCase);

// Routes
var group = app.MapGroup("/api/users").WithTags("Users");

group.MapGet("/", (int page = 1, int pageSize = 50) =>
{
    if (page < 1) page = 1;
    if (pageSize < 1 || pageSize > 200) pageSize = 50;

    var snapshot = users.Values.ToArray();
    var total = snapshot.LongLength;
    var items = snapshot
        .OrderBy(u => u.LastName)
        .ThenBy(u => u.FirstName)
        .Skip((page - 1) * pageSize)
        .Take(pageSize)
        .ToList();

    return Results.Ok(new PagedResult<User>(items, total, page, pageSize));
})
.WithName("GetUsers");

group.MapGet("/{id:guid}", (Guid id) =>
{
    return users.TryGetValue(id, out var user)
        ? Results.Ok(user)
        : Results.NotFound(new { message = "User not found" });
})
.WithName("GetUserById");

group.MapPost("/", (CreateUserRequest? req) =>
{
    if (req is null)
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["body"] = ErrorArrays.BodyRequired
        });

    var errors = Validators.ValidateCreate(req);
    if (errors.Count > 0)
        return Results.ValidationProblem(errors);

    var normalizedEmail = req.Email.Trim().ToLowerInvariant();
    var newId = Guid.NewGuid();

    if (!emailIndex.TryAdd(normalizedEmail, newId))
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["email"] = ErrorArrays.EmailExists
        });

    var user = new User
    {
        Id = newId,
        FirstName = req.FirstName.Trim(),
        LastName = req.LastName.Trim(),
        Email = normalizedEmail,
        Department = req.Department?.Trim(),
        IsActive = true,
        CreatedAtUtc = DateTime.UtcNow,
        UpdatedAtUtc = null
    };

    users[user.Id] = user;
    return Results.CreatedAtRoute("GetUserById", new { id = user.Id }, user);
})
.WithName("CreateUser");

group.MapPut("/{id:guid}", (Guid id, UpdateUserRequest? req) =>
{
    if (req is null)
        return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            ["body"] = ErrorArrays.BodyRequired
        });

    if (!users.TryGetValue(id, out var existing))
        return Results.NotFound(new { message = "User not found" });

    var errors = Validators.ValidateUpdate(req);
    if (errors.Count > 0)
        return Results.ValidationProblem(errors);

    var newEmail = string.IsNullOrWhiteSpace(req.Email)
        ? existing.Email
        : req.Email.Trim().ToLowerInvariant();

    if (!newEmail.Equals(existing.Email, StringComparison.OrdinalIgnoreCase))
    {
        if (!emailIndex.TryAdd(newEmail, id))
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["email"] = ErrorArrays.EmailExists
            });

        emailIndex.TryRemove(existing.Email, out _);
    }

    var updated = existing with
    {
        FirstName = string.IsNullOrWhiteSpace(req.FirstName) ? existing.FirstName : req.FirstName.Trim(),
        LastName = string.IsNullOrWhiteSpace(req.LastName) ? existing.LastName : req.LastName.Trim(),
        Email = newEmail,
        Department = req.Department is null
            ? existing.Department
            : (req.Department.Length == 0 ? null : req.Department.Trim()),
        IsActive = req.IsActive ?? existing.IsActive,
        UpdatedAtUtc = DateTime.UtcNow
    };

    users[id] = updated;
    return Results.Ok(updated);
})
.WithName("UpdateUser");

group.MapDelete("/{id:guid}", (Guid id) =>
{
    if (!users.TryRemove(id, out var deleted))
        return Results.NotFound(new { message = "User not found" });

    emailIndex.TryRemove(deleted.Email, out _);
    return Results.NoContent();
})
.WithName("DeleteUser");

app.Run();

#region Models, Validators & Middleware

public record User
{
    public Guid Id { get; init; }
    public required string FirstName { get; init; }
    public required string LastName { get; init; }
    public required string Email { get; init; } // normalized lower-case
    public string? Department { get; init; }
    public bool IsActive { get; init; } = true;
    public DateTime CreatedAtUtc { get; init; }
    public DateTime? UpdatedAtUtc { get; init; }
}

public record CreateUserRequest(string FirstName, string LastName, string Email, string? Department);
public record UpdateUserRequest(string? FirstName, string? LastName, string? Email, string? Department, bool? IsActive);
public record PagedResult<T>(IReadOnlyCollection<T> Items, long Total, int Page, int PageSize);

public static class ErrorArrays
{
    public static readonly string[] Required = new[] { "Required" };
    public static readonly string[] InvalidEmail = new[] { "Invalid format" };
    public static readonly string[] EmailExists = new[] { "Email already exists" };
    public static readonly string[] BodyRequired = new[] { "Request body is required" };
}

public static class Validators
{
    public static Dictionary<string, string[]> ValidateCreate(CreateUserRequest req)
    {
        var errors = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

        if (string.IsNullOrWhiteSpace(req.FirstName))
            errors["firstName"] = ErrorArrays.Required;

        if (string.IsNullOrWhiteSpace(req.LastName))
            errors["lastName"] = ErrorArrays.Required;

        if (string.IsNullOrWhiteSpace(req.Email))
        {
            errors["email"] = ErrorArrays.Required;
        }
        else if (!IsValidEmail(req.Email))
        {
            errors["email"] = ErrorArrays.InvalidEmail;
        }

        if (req.FirstName?.Length > 100)
            errors["firstName"] = new[] { "Max length is 100" };

        if (req.LastName?.Length > 100)
            errors["lastName"] = new[] { "Max length is 100" };

        if (req.Department?.Length > 100)
            errors["department"] = new[] { "Max length is 100" };

        return errors;
    }

    public static Dictionary<string, string[]> ValidateUpdate(UpdateUserRequest req)
    {
        var errors = new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(req.Email) && !IsValidEmail(req.Email))
            errors["email"] = ErrorArrays.InvalidEmail;

        if (req.FirstName is { Length: > 100 })
            errors["firstName"] = new[] { "Max length is 100" };

        if (req.LastName is { Length: > 100 })
            errors["lastName"] = new[] { "Max length is 100" };

        if (req.Department is { Length: > 100 })
            errors["department"] = new[] { "Max length is 100" };

        return errors;
    }

    private static bool IsValidEmail(string email)
    {
        try { _ = new MailAddress(email); return true; }
        catch { return false; }
    }
}

// === Middleware: Error Handling ===
public sealed class SimpleErrorHandlingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SimpleErrorHandlingMiddleware> _logger;

    public SimpleErrorHandlingMiddleware(RequestDelegate next, ILogger<SimpleErrorHandlingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        try
        {
            await _next(context);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unhandled exception");
            if (!context.Response.HasStarted)
            {
                context.Response.Clear();
                context.Response.StatusCode = StatusCodes.Status500InternalServerError;
                context.Response.ContentType = "application/json";
            }
            var payload = JsonSerializer.Serialize(new { error = "Internal server error." });
            await context.Response.WriteAsync(payload);
        }
    }
}

// === Middleware: Token Authentication ===
public static class AuthOptions
{
    // Set environment variable API_TOKEN to override in non-dev.
    public static readonly string ApiToken = Environment.GetEnvironmentVariable("API_TOKEN") ?? "dev-token-123";

    public static bool ValidateToken(string? token) =>
        !string.IsNullOrWhiteSpace(token) &&
        token.Equals(ApiToken, StringComparison.Ordinal);
}

public sealed class TokenAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<TokenAuthMiddleware> _logger;

    public TokenAuthMiddleware(RequestDelegate next, ILogger<TokenAuthMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path;

        // Allow unauthenticated access to Swagger and error endpoints
        if (path.StartsWithSegments("/swagger") || path.StartsWithSegments("/error") || context.Request.Method.Equals("OPTIONS", StringComparison.OrdinalIgnoreCase))
        {
            await _next(context);
            return;
        }

        // Enforce token only for API routes
        if (path.StartsWithSegments("/api"))
        {
            if (!context.Request.Headers.TryGetValue("Authorization", out var authHeader) ||
                !authHeader.ToString().StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(new { error = "Unauthorized" }));
                return;
            }

            var token = authHeader.ToString().Substring("Bearer ".Length).Trim();
            if (!AuthOptions.ValidateToken(token))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(JsonSerializer.Serialize(new { error = "Unauthorized" }));
                return;
            }
        }

        await _next(context);
    }
}

// === Middleware: Request/Response Logging ===
public sealed class RequestResponseLoggingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<RequestResponseLoggingMiddleware> _logger;

    public RequestResponseLoggingMiddleware(RequestDelegate next, ILogger<RequestResponseLoggingMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var method = context.Request.Method;
        var path = context.Request.Path.Value ?? "/";

        await _next(context);

        var status = context.Response.StatusCode;
        _logger.LogInformation("HTTP {Method} {Path} => {StatusCode}", method, path, status);
    }
}

// === Middleware extensions ===
public static class MiddlewareExtensions
{
    public static IApplicationBuilder UseSimpleErrorHandler(this IApplicationBuilder app) =>
        app.UseMiddleware<SimpleErrorHandlingMiddleware>();

    public static IApplicationBuilder UseTokenAuth(this IApplicationBuilder app) =>
        app.UseMiddleware<TokenAuthMiddleware>();

    public static IApplicationBuilder UseRequestResponseLogging(this IApplicationBuilder app) =>
        app.UseMiddleware<RequestResponseLoggingMiddleware>();
}

#endregion
