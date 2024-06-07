using BaseLibrary.DTOs;
using BaseLibrary.Entites;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.VisualBasic;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using System.Data;
using Constants = ServerLibrary.Helpers.Constants;

namespace ServerLibrary.Repositories.Implementations
{
    public class UserAccountRepository : IUserAccount
    {
        private readonly IOptions<JwtSection> _config;
        private readonly AppDBContext appDBContext;

        public UserAccountRepository(IOptions<JwtSection> config, AppDBContext _appDBContext)
        {
            _config = config;
            appDBContext = _appDBContext!;
        }
        public async Task<GeneralResponse> CreateAsync(Register user)
        {
            if (user == null) return new GeneralResponse(false, "User Is null");

            var checkUser = await appDBContext.ApplicationUsers.FirstOrDefaultAsync(i => i.Email == user.Email);
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

        public Task<GeneralResponse> SignInAsync(Login user)
        {
            throw new NotImplementedException();
        }

        private async Task<ApplicationUser?> FindUserByEmailAsync(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
            {
                throw new ArgumentException("Email cannot be null or whitespace.", nameof(email));
            }

            return await appDBContext.ApplicationUsers
                .FirstOrDefaultAsync(i => i.Email != null && i.Email.ToLower() == email.ToLower());
        }
        private async Task<T> AddtoDataBase<T>(T model)
        {
            var result = appDBContext.Add(model!);
            await appDBContext.SaveChangesAsync();
            return (T)result.Entity;
        }
    }
}
