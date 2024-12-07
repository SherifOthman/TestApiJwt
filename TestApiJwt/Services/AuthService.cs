using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Reflection.Metadata.Ecma335;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using TestApiJwt.Helpers;
using TestApiJwt.Models;

namespace TestApiJwt.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly JWT _jwt;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        RoleManager<IdentityRole> roleManager,
        IOptionsMonitor<JWT> IOptions
        )
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _roleManager = roleManager;
        _jwt = IOptions.CurrentValue;
    }

    public async Task<AuthModel> RegisterAsync(RegisterModel model)
    {
        if (await _userManager.FindByEmailAsync(model.Email) is not null)
            return new AuthModel { Message = "Email is already registered!" };

        if (await _userManager.FindByNameAsync(model.Username) is not null)
            return new AuthModel { Message = "Username is already registered!" };


        ApplicationUser user = new ApplicationUser()
        {
            UserName = model.Username,
            Email = model.Email,
            FirstName = model.FirstName,
            LastName = model.LastName,
        };

        var result = await _userManager.CreateAsync(user, model.Password);

        if (!result.Succeeded)
        {
            string errors = string.Empty;

            foreach (var error in result.Errors)
            {
                errors += $"{error.Description}, ";
            }

            return new AuthModel { Message = errors };
        }

        await _userManager.AddToRoleAsync(user, "User");

        var jwtSecurityToken = await GenerateJwtTokenAsync(user);


        return new AuthModel
        {
            Email = user.Email,
            //ExpiresOn = jwtSecurityToken.ValidTo,
            IsAuthenticated = true,
            Roles = new List<string> { "User" },
            Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
            Username = user.UserName,
        };
    }

    public async Task<AuthModel> GetTokenAsync(TokenRequestModel model)
    {
        var authModel = new AuthModel();

        // Find user by email
        var user = await _userManager.FindByEmailAsync(model.Email);

        // Check if user exists
        if (user == null)
        {
            authModel.Message = "Email or Password is incorrect";
            return authModel;
        }

        // Check password and handle lockout
        var signInResult = await _signInManager.CheckPasswordSignInAsync(user, model.Password, lockoutOnFailure: true);

        if (!signInResult.Succeeded)
        {
            // Handle lockout scenario
            if (signInResult.IsLockedOut)
            {
                authModel.Message = "Your account is locked. Please try again later.";
                authModel.Message += $"\nTry again after: {await GetLockoutTimeLeftAsync(user)}";

                return authModel;
            }

            // Handle incorrect password scenario
            authModel.Message = "Email or Password is incorrect";
            authModel.Message += $"\nTrails: {await _userManager.GetAccessFailedCountAsync(user)}";
            return authModel;
        }

        // Generate JWT token
        JwtSecurityToken jwtSecurityToken = await GenerateJwtTokenAsync(user);
        var userRoles = await _userManager.GetRolesAsync(user);

        // Set auth model properties
        authModel.IsAuthenticated = true;
        authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
        authModel.Email = user.Email;
        authModel.Username = user.UserName;
        // authModel.ExpiresOn = jwtSecurityToken.ValidTo;
        authModel.Roles = userRoles.ToList();

        if (user.RefreshTokens.Any(t => t.IsActive))
        {
            var activeRefreshToken = user.RefreshTokens.FirstOrDefault(t => t.IsActive);
            authModel.RefreshToken = activeRefreshToken.Token;
            authModel.RefreshTokenExpiration = activeRefreshToken.ExpiresOn;
        }
        else
        {
            var refreshToken = GenerateRefreshToken();
            authModel.RefreshToken = refreshToken.Token;
            authModel.RefreshTokenExpiration = refreshToken.ExpiresOn;
            user.RefreshTokens.Clear();
            user.RefreshTokens.Add(refreshToken);
            await _userManager.UpdateAsync(user);
        }

        return authModel;
    }

    public async Task<string?> GetLockoutTimeLeftAsync(ApplicationUser user)
    {
        // Get the lockout end date
        var lockoutEndDate = await _userManager.GetLockoutEndDateAsync(user);

        // Check if the lockoutEndDate is null or in the past
        if (lockoutEndDate == null || lockoutEndDate <= DateTimeOffset.UtcNow)
        {
            return null; // No lockout or lockout has expired
        }

        // Calculate the remaining time
        var timeLeft = lockoutEndDate.Value - DateTimeOffset.UtcNow;

        // Extract minutes and seconds
        int minutes = (int)timeLeft.TotalMinutes;
        int seconds = timeLeft.Seconds;

        // Return formatted time
        return $"{minutes} minutes and {seconds} seconds";
    }

    public async Task<string> AddRoleAsync(AddRoleModel model)
    {
        var user = await _userManager.FindByIdAsync(model.UserId);

        if (user is null || !await _roleManager.RoleExistsAsync(model.Role))
            return "Invalid User ID or Role";

        if (await _userManager.IsInRoleAsync(user, model.Role))
            return "User already assigned to this role";

        var result = await _userManager.AddToRoleAsync(user, model.Role);

        return result.Succeeded ? string.Empty : "Something went wrong!";
    }

    public async Task<AuthModel> RefreshTokenAsync(string token)
    {
        var authModel = new AuthModel();

        var user = await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));

        if (user == null)
        {
            authModel.Message = "Invalid Token";
            return authModel;
        }

        var refreshToken = user.RefreshTokens.Single(t => t.Token == token);

        if (!refreshToken.IsActive)
        {
            authModel.Message = "Inactive token";
            return authModel;
        }

        refreshToken.RevokedOn = DateTime.UtcNow;

        var newRefreshToken = GenerateRefreshToken();

        user.RefreshTokens.Add(refreshToken);
        await _userManager.UpdateAsync(user);

        var jwtToken = await GenerateJwtTokenAsync(user);

        authModel.IsAuthenticated = true;
        authModel.Username = user.UserName;
        authModel.Email = user.Email;
        authModel.Roles = (await _userManager.GetRolesAsync(user)).ToList();
        authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtToken);
        authModel.RefreshToken = newRefreshToken.Token;
        authModel.RefreshTokenExpiration = newRefreshToken.ExpiresOn;

        return authModel;
    }

    public async Task<bool> RevokeTokenAsync(string token)
    {
        var authModel = new AuthModel();

        var user = await _userManager.Users.SingleOrDefaultAsync(u => u.RefreshTokens.Any(t => t.Token == token));

        if (user == null)
            return false;

        var refreshToken = user.RefreshTokens.Single(t => t.Token == token);

        if (!refreshToken.IsActive)
            return false;

        refreshToken.RevokedOn = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        return true;
    }

    private async Task<JwtSecurityToken> GenerateJwtTokenAsync(ApplicationUser user)
    {
        // Retrieve user claims and roles
        var userSpecificClaims = await _userManager.GetClaimsAsync(user);
        var userRoles = await _userManager.GetRolesAsync(user);


        // Convert Roles into claims
        var roleClaims = userRoles.Select(role => new Claim("roles", role)).ToList();

        // Combine all claims
        var jwtClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user?.UserName!), // Subject (UserName)
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Unique JWT ID
                new Claim(JwtRegisteredClaimNames.Email, user?.Email!), // Email address
                new Claim("uid", user?.Id!) // User Identifier
            }
        .Union(userSpecificClaims) // Add user-specific claims
        .Union(roleClaims); // Add role claims

        // Create the signing credentials using the secret key
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
        var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        // Build the JWT Token
        var jwtToken = new JwtSecurityToken(
            issuer: _jwt.Issuer,
            audience: _jwt.Aduience,
            claims: jwtClaims,
            expires: DateTime.Now.AddMinutes(_jwt.DurationInDays),
            signingCredentials: signingCredentials
            );

        return jwtToken;
    }

    private RefreshToken GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        RandomNumberGenerator.Fill(randomNumber);

        return new RefreshToken
        {
            Token = Convert.ToBase64String(randomNumber),
            CreatedOn = DateTime.UtcNow,
            ExpiresOn = DateTime.UtcNow.AddDays(10),
        };
    }

}
