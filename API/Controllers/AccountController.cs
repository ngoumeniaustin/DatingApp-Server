using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using API.Services;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace API.Controllers
{
  public class AccountController:BasicApiController
  {
    private readonly DataContext context;
    private readonly ITokenService tokenService;
    public AccountController(DataContext context, ITokenService tokenService)
    {
      this.tokenService = tokenService;
      this.context = context;

    }

    [HttpPost("register")] // POST  api/account/register
    public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto)
    {

        if(await UserExist(registerDto.Username)) return BadRequest("Username is taken");
        
        using var hmac = new HMACSHA512();

        var user = new AppUser()
        {
            UserName = registerDto.Username.ToLower(),
            PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
            PasswordSalt = hmac.Key
        };

        context.Users.Add(user);
        await context.SaveChangesAsync();

        return new UserDto{
          Username = user.UserName,
          Token = this.tokenService.CreateToken(user)
        };
    }

    private async Task<bool> UserExist(string username)
    {
         return await context.Users.AnyAsync(x => x.UserName == username.ToLower());   
    }

    [HttpPost("login")] 
    public async Task<ActionResult<UserDto>> Loging(LoginDto loginDto)
    {
            var user = await context.Users.SingleOrDefaultAsync(x => x.UserName == loginDto.Username.ToLower());

            if(user == null) return Unauthorized("invalid username");

            
            using var hmac = new HMACSHA512(user.PasswordSalt);
            var computeHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

            for(int i = 0;i< computeHash.Count();i++){
                if(computeHash[i] != user.PasswordHash[i]) return Unauthorized("invalid password");

            }
            
            return new UserDto{
              Username = user.UserName,
              Token = this.tokenService.CreateToken(user)
            };

    }

  }
}