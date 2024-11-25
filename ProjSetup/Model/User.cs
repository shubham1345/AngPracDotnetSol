using Microsoft.AspNetCore.Identity;

namespace ProjSetup.Model
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; }
        public string PasswordHash { get; set; } // Store hashed passwords
        public string? RefreshToken { get; set; }
        public DateTime RefreshTokenExpiryTime { get; set; }
        public List<string> Roles { get; set; }
    }

    public class RefreshToken
    {
        public string Token { get; set; }
        public DateTime ExpiryDate { get; set; }
        public int UserId { get; set; }
        public User User { get; set; }
    }

    public class JwtSettings
    {
        public string Secret { get; set; }
        public TimeSpan AccessTokenExpiration { get; set; }
        public TimeSpan RefreshTokenExpiration { get; set; }
    }
    public class TokenDto
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }
    public class LoginDto
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

}
