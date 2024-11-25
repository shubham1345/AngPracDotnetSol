using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using ProjSetup.Model;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseInMemoryDatabase("InMemoryDb"));

builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("JwtSettings"));

var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>();

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
            System.Text.Encoding.ASCII.GetBytes(jwtSettings.Secret)),
        ValidateIssuer = false,
        ValidateAudience = false,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddScoped<TokenService>();
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("UserOnly", policy => policy.RequireRole("User"));
});
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(
        builder =>
        {

            //you can configure your custom policy
            builder.AllowAnyOrigin()
                                .AllowAnyHeader()
                                .AllowAnyMethod();
        });
});


var app = builder.Build();

// Seed the database
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    SeedDatabase(context);
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseCors();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

// Method to seed the database
void SeedDatabase(ApplicationDbContext context)
{
    if (!context.Users.Any())
    {
        var user = new List<User>
        {
            new User { Id = 1,
            Username = "testuser",
            PasswordHash = ComputeHash("password123"), // Replace with a hashed password
            RefreshToken = null,
            RefreshTokenExpiryTime = DateTime.UtcNow,
            Roles = new List<string> { "admin" } // Example roles
            },
             new User { Id = 2,
            Username = "testuser2",
            PasswordHash = ComputeHash("password123"), // Replace with a hashed password
            RefreshToken = null,
            RefreshTokenExpiryTime = DateTime.UtcNow,
            Roles = new List<string> { "phc" } // Example roles
            },
             new User { Id = 3,
            Username = "testuser3",
            PasswordHash = ComputeHash("password123"), // Replace with a hashed password
            RefreshToken = null,
            RefreshTokenExpiryTime = DateTime.UtcNow,
            Roles = new List<string> { "user" } // Example roles
            }
        };

        context.Users.AddRange(user);
        context.SaveChanges();
    }
}

string ComputeHash(string password)
{
    using var hmac = new System.Security.Cryptography.HMACSHA512(Encoding.UTF8.GetBytes(password));
    var computedHash = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(password)));
    return computedHash;
}
