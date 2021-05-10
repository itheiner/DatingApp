using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _context = context;

        }

        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
        {
            //check to see if the user exists
            if (await UserExists(registerDto.Username)) return BadRequest("Username is taken");

            using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = registerDto.Username.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };

            _context.Users.Add(user);//this is just setting it to be tracked by ef
            await _context.SaveChangesAsync();//commit these changes

            return new UserDto{
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }

        private async Task<bool> UserExists(string username)
        {
            //this will return true if the user exists
            return await _context.Users.AnyAsync(x => x.UserName == username.ToLower());
        }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto loginDto)
        {
            //this will see search for only on instance of the username
            //it will throw and exception if there are more than one
            var user = await _context.Users.SingleOrDefaultAsync(x => x.UserName == loginDto.Username.ToLower());
            //if the user ends up being null, then you will get a response of
            //unathorized user
            if (user == null) return Unauthorized("Invalid Username");
            //if we get this far then we have a valid username
            //lets now check the password
            using var hmac = new HMACSHA512(user.PasswordSalt);

            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));
            //lets compare the hashes
            //because it is a byte array we have to loop over each item in the array
            for (int i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != user.PasswordHash[i]) return Unauthorized("Invalid Password");
            }

            //if we got to here the user is valid and the password matches
            return new UserDto{
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };
        }
    }
}