using BaseLibrary.DTOs;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;
using ServerLibrary.Repositories.Contracts;

namespace Server.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController(IUserAccount accountInterface) : ControllerBase
    {
        [HttpPost("register")]
        public async Task<IActionResult> CreateAsync(Register User)
        {
            if (User == null) return BadRequest("Model is empty");
            var result = await accountInterface.CreateAsync(User);
            return Ok(result);

        }

        [HttpPost("login")]
        public async Task<IActionResult> SignInAsync(Login User)
        {
            if (User == null) return BadRequest("Model is empty");
            var result = await accountInterface.SignInAsync(User);
            return Ok(result);
        }

        [HttpPost("RefreshToken")]
        public async Task<IActionResult> RefreshTokenAsync(RefreshToken token)
        {
            if (token == null) return BadRequest("token is empty");
            var result = await accountInterface.RefreshTokenAsync(token);
            return Ok(result);
        }
    }
}
