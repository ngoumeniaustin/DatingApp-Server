using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{

 
  public class UsersController:BasicApiController
  {
    private readonly DataContext context;
  
    public UsersController(DataContext context)
    {
      this.context = context;
        
    }

    [HttpGet]
    public async Task<ActionResult<IEnumerable<AppUser>>> GetUsers(){

        var users = await this.context.Users.ToListAsync();

        return users;
    }
    [Authorize]
    [HttpGet("{id}")]
    public async Task<ActionResult<AppUser>> GetUser(int id)
    {
        var user = await context.Users.FindAsync(id);
        return user;
    }

  }
}