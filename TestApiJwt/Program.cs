using Azure.Core;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using Scalar.AspNetCore;
using System.Text;
using System.Threading.RateLimiting;
using TestApiJwt.Helpers;
using TestApiJwt.Middlewares;
using TestApiJwt.Models;
using TestApiJwt.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();


builder.Services.Configure<JWT>(builder.Configuration.GetSection("JWT"));
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>();

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(2);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
});

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
    .AddJwtBearer(options =>
    {
        JWT? jwt = builder.Configuration.GetSection("JWT").Get<JWT>();

        options.RequireHttpsMetadata = false;
        options.SaveToken = false;
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuerSigningKey = true,
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidIssuer = jwt?.Issuer,
            ValidAudience = jwt?.Aduience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt?.Key!)),
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

builder.Services.AddScoped<IAuthService, AuthService>();

builder.Services.AddRateLimiter(rateLimiterOptions =>
{
    rateLimiterOptions.AddFixedWindowLimiter("fixed", options =>
    {
        options.PermitLimit = 2; // Allow up to 5 requests
        options.Window = TimeSpan.FromSeconds(30); // Per 1-minute window
        options.QueueProcessingOrder = QueueProcessingOrder.OldestFirst;
        //options.QueueLimit = 2; // Allow 2 requests to queue if limit is reached

    });
    rateLimiterOptions.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    rateLimiterOptions.OnRejected = async (context, _) =>
    {
       await context.HttpContext.Response.WriteAsJsonAsync("You have reached the mxmuim limit of requests.");
    };
});

builder.Services.AddTransient<ErrorHandlingMiddleware>();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

app.UseMiddleware<ErrorHandlingMiddleware>();

app.UseHttpsRedirection();
app.UseRateLimiter();

//app.UseExceptionHandler(appError =>
//{
//    appError.Run(async context =>
//    {
//        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
//        context.Response.ContentType = "application/json";

//        var contextFeature = context.Features.Get<IExceptionHandlerFeature>();
//        if (contextFeature != null)
//        {
//            Console.WriteLine($"Error: {contextFeature.Error}");
//        }
//        await context.Response.WriteAsJsonAsync(new
//        {
//            StatusCode = context.Response.StatusCode,
//            Message = "Internal Server Error"
//        });
//    });
//});

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
