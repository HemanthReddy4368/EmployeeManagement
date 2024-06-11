using BaseLibrary.DTOs;
using BaseLibrary.Entites;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using System.Data;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Constants = ServerLibrary.Helpers.Constants;

namespace ServerLibrary.Repositories.Implementations
{
    public class UserAccountRepository : IUserAccount
    {
        private readonly IOptions<JwtSection> config;
        private readonly AppDBContext appDBContext;

        // Refrencing the appDBcontext and config in constructor
        public UserAccountRepository(IOptions<JwtSection> _config, AppDBContext _appDBContext)
        {
            config = _config;
            appDBContext = _appDBContext!;
        }
        // Create Async Implementation
        public async Task<GeneralResponse> CreateAsync(Register user)
        {
            if (user == null) return new GeneralResponse(false, "User Is null");

            var checkUser = await appDBContext.ApplicationUsers.FirstOrDefaultAsync(i=>i.Email == user.Email);
            if (checkUser != null) return new GeneralResponse(false, "User already exist");

            //save the user
            var applicationUser = await AddtoDataBase(new ApplicationUser()
            {
                Fullname = user.Fullname,
                Email = user.Email,
                Password = BCrypt.Net.BCrypt.HashPassword(user.Password)
            });

            // check user and assign the role
            var checkAdminRole = await appDBContext.SystemRoles.FirstOrDefaultAsync(i => i.Name!.Equals(Constants.Admin));
            if (checkAdminRole is null)
            {
                var createAdminRole = await AddtoDataBase(new SystemRole() { Name = Constants.Admin });
                await AddtoDataBase(new UserRole() { RoleId = createAdminRole.Id, UserId = applicationUser.Id });
                return new GeneralResponse(true, "User Created Successfully");
            }

            var checkUserRole = await appDBContext.SystemRoles.FirstOrDefaultAsync(i => i.Name!.Equals(Constants.User));
            SystemRole response = new();
            if (checkUserRole is null)
            {
                response = await AddtoDataBase(new SystemRole() { Name = Constants.User});
                await AddtoDataBase(new UserRole() { RoleId=response.Id, UserId=applicationUser.Id });
            }
            else
            {
                await AddtoDataBase(new UserRole() { RoleId = checkUserRole.Id, UserId=applicationUser.Id });
            }
            return new GeneralResponse(true,"Account Created");
        }
        //Method to get the User Role Id
        private async Task<UserRole> FindRoleAsync(int  Id)
        {
            return await appDBContext.UserRoles.FirstOrDefaultAsync(i => i.UserId == Id);
        }
        // Method to find the User Role Name
        private async Task<SystemRole> FindRoleName(int roleId)
        {
            return await appDBContext.SystemRoles.FirstOrDefaultAsync(i => i.Id == roleId);
        }
        //SignInAsync Implementation
        public async Task<LoginResponse> SignInAsync(Login user)
        {
            if(user is null) { return new LoginResponse(false,"User not Found"); }
            var checkuser = await appDBContext.ApplicationUsers.FirstOrDefaultAsync(i=>i.Email==user.Email);

            if (checkuser is null) { return new LoginResponse(false, "No User with that email"); }

            // verify the password. compare the password that is entered by user and database password

            if (!BCrypt.Net.BCrypt.Verify(user.Password, checkuser.Password))
            {
                return new LoginResponse(false, "Password not Valid");
            }

            // If password is correct and user is present get the user role

            var getUserRole = await FindRoleAsync(checkuser.Id);
            if (getUserRole is null)
            {
                return new LoginResponse(false, "User Role Not Found");
            }

            // From the userroles we will get only roleid from system roles we need to get the actual role

            var getRoleName = await FindRoleName(getUserRole.Id);
            if (getRoleName is null)
            {
                return new LoginResponse(false, "User Role Name not found");
            }

            // JWT Tokens
            string jwtToken = GenerateToken(checkuser, getRoleName.Name);
            string ReferenceToken = GenerateRefreshToken();

            var findUser = await appDBContext.RefreshTokens.FirstOrDefaultAsync(i => i.UserId == checkuser.Id);
            if (findUser is not null)
            {
                findUser.Token = ReferenceToken;
                await appDBContext.SaveChangesAsync();
            }
            else
            {
                await AddtoDataBase(new RefreshTokenInfo()
                {
                    Token = ReferenceToken,
                    UserId = checkuser.Id
                });
            }
            return new LoginResponse(true, "Login Successfull",jwtToken,ReferenceToken);
        }
        // Genrate Token method
        private string GenerateToken(ApplicationUser user, string role)
        {
            var securitykey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config.Value.key!));
            var credintials = new SigningCredentials(securitykey,SecurityAlgorithms.HmacSha256);
            var userclaims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Fullname),
                new Claim(ClaimTypes.Email,user.Email),
                new Claim(ClaimTypes.Role,role!)
            };

            var token = new JwtSecurityToken(
                issuer: config.Value.Issuer,
                audience: config.Value.Audience,
                claims: userclaims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: credintials);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        // Random function
        private static string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        private async Task<ApplicationUser?> FindUserByEmailAsync(Register user)
        {
            Register user1 = user;
            return await appDBContext.ApplicationUsers
                .FirstOrDefaultAsync(i=>i.Email == user.Email);
        }
        private async Task<T> AddtoDataBase<T>(T model)
        {
            var result = appDBContext.Add(model!);
            await appDBContext.SaveChangesAsync();
            return (T)result.Entity;
        }
        // Refresh Token Async Implementation
        public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
        {
            if (token == null) { return new LoginResponse(false, "Model is empty"); }
            // Get RefreshToken using token
            var RefreshToken = await appDBContext.RefreshTokens.FirstOrDefaultAsync(i => i.Token!.Equals(token.Token));
            if (RefreshToken == null) { return new LoginResponse(false,"RefreshToken not found"); }

            // Get the user Details
            var User = await appDBContext.ApplicationUsers.FirstOrDefaultAsync(i=>i.Id.Equals(RefreshToken.UserId));
            if (User == null) { return new LoginResponse(false, "Refresh Token Not created due to User not found"); }

            var UserRole = await FindRoleAsync(User.Id);
            var RoleName = await FindRoleName(UserRole.Id);
            string jwtToken = GenerateToken(User, RoleName.Name!);
            string refreshToken = GenerateRefreshToken();

            // save changes to DB
            var UpdatedRefreshToken = await appDBContext.RefreshTokens.FirstOrDefaultAsync(i => i.UserId == User.Id);
            if (UpdatedRefreshToken == null)
            {
                return new LoginResponse(false, "Refresh token failed to generate as no user logeed in");
            }
            UpdatedRefreshToken.Token = refreshToken;
            await appDBContext.SaveChangesAsync();
            return new LoginResponse(true, "Refresh Token successfully generated",jwtToken,refreshToken);



        }
    }
}
