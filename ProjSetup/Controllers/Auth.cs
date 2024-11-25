using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using ProjSetup.Model;
using System.Security.Claims;
using System.Text;

[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly ApplicationDbContext _context;
    private readonly TokenService _tokenService;
    private readonly JwtSettings _jwtSettings;

    public AuthController(ApplicationDbContext context, TokenService tokenService, IOptions<JwtSettings> jwtSettings)
    {
        _context = context;
        _tokenService = tokenService;
        _jwtSettings = jwtSettings.Value;
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
    {
        var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == loginDto.Username);
        if (user == null || !VerifyPasswordHash(loginDto.Password, user.PasswordHash))
        {
            return Unauthorized();
        }

        var claims = new[]
        {
            new Claim(ClaimTypes.Name, user.Username),
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString())
        }.Concat(user.Roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var accessToken = _tokenService.GenerateAccessToken(claims);
        var refreshToken = _tokenService.GenerateRefreshToken();
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.Add(_jwtSettings.RefreshTokenExpiration);
        _context.Users.Update(user);
        await _context.SaveChangesAsync();

        return Ok(new
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken
        });
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] TokenDto tokenDto)
    {
        var principal = _tokenService.GetPrincipalFromExpiredToken(tokenDto.AccessToken);
        if (principal == null)
        {
            return BadRequest("Invalid access token or refresh token");
        }

        var username = principal.Identity.Name;
        var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == username);

        if (user == null || user.RefreshToken != tokenDto.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.UtcNow)
        {
            return Unauthorized();
        }

        var newAccessToken = _tokenService.GenerateAccessToken(principal.Claims);
        var newRefreshToken = _tokenService.GenerateRefreshToken();

        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.Add(_jwtSettings.RefreshTokenExpiration);
        _context.Users.Update(user);
        await _context.SaveChangesAsync();

        return Ok(new
        {
            AccessToken = newAccessToken,
            RefreshToken = newRefreshToken
        });
    }
    [HttpGet("GetUserRoles")]
    public async Task<IActionResult> GetUserRoles(string username)
    {
        var user = await _context.Users.SingleOrDefaultAsync(u => u.Username == username);

        return Ok(user != null ? (user.Roles!= null ? user.Roles[0]:"" ): "");
    }

    private bool VerifyPasswordHash(string password, string storedHash)
    {
        using var hmac = new System.Security.Cryptography.HMACSHA512(Encoding.UTF8.GetBytes(password));
        var computedHash = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(password)));
        return storedHash == computedHash;
    }
}
