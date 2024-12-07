using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using System.ComponentModel.DataAnnotations;

namespace TestApiJwt.Models;

public class ApplicationUser : IdentityUser
{
    [Required, MaxLength(50)]
    public string FirstName { get; set; } = null!;

    [Required, MaxLength(50)]
    public string LastName { get; set; } = null!;
    public List<RefreshToken>? RefreshTokens { get; set; }
}
