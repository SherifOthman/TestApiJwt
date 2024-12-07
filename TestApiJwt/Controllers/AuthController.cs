using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TestApiJwt.Models;
using TestApiJwt.Services;

namespace TestApiJwt.Controllers;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    [HttpPost("Register")]
    public async Task<IActionResult> RegisterAsync([FromBody] RegisterModel model)
    {
        if (!ModelState.IsValid)
            return BadRequest(model);

        var result = await _authService.RegisterAsync(model);

        if (!result.IsAuthenticated)
            return BadRequest(result.Message);

        SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);

        return Ok(result);
    }

    [HttpPost("Token")]
    public async Task<IActionResult> GetTokenAsync([FromBody] TokenRequestModel model)
    {
        if (!ModelState.IsValid)
            return BadRequest(model);

        var result = await _authService.GetTokenAsync(model);

        if (!result.IsAuthenticated)
            return BadRequest(result.Message);

        if (!string.IsNullOrEmpty(result.RefreshToken))
            SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);

        return Ok(result);
    }

    [HttpPost("AddRole")]
    public async Task<IActionResult> AddRoleAsync([FromBody] AddRoleModel model)
    {
        if (!ModelState.IsValid)
            return BadRequest(model);

        var result = await _authService.AddRoleAsync(model);

        if (!string.IsNullOrEmpty(result))
            return BadRequest(result);

        return Ok(result);
    }

    [HttpGet("RefreshToken")]
    public async Task<IActionResult> RefreshToken()
    {
        var refreshToken = Request.Cookies["RefreshToken"];
        var result = await _authService.RefreshTokenAsync(refreshToken);

        if (!result.IsAuthenticated)
            return BadRequest(result);

        SetRefreshTokenInCookie(result.RefreshToken, result.RefreshTokenExpiration);

        return Ok(result);
    }

    [HttpPost("Revoke-Token")]
    public async Task<IActionResult> RevokeToken([FromBody] RevokeToken model)
    {
        var token = model.Token ?? Request.Cookies["RefreshToken"];

        if (string.IsNullOrEmpty(token))
            return BadRequest("Token is required!");

        var result = await _authService.RevokeTokenAsync(token);

        if (!result)
            return BadRequest("Token Is Invalid");

        return Ok("Token is revoked");
    }

    private void SetRefreshTokenInCookie(string refreshToken, DateTime expires)
    {
        var cookieOptions = new CookieOptions()
        {
            HttpOnly = true,
            Expires = expires.ToLocalTime(),
        };

        Response.Cookies.Append("RefreshToken", refreshToken, cookieOptions);
    }


}