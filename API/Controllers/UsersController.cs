using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{

  [ApiController]
  [Route("api/[controller]")] // localh..../api/users(name of controller)
  public class UsersController:ControllerBase
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

    [HttpGet("{id}")]
    public async Task<ActionResult<AppUser>> GetUser(int id)
    {
        var user = await context.Users.FindAsync(id);
        return user;
    }

  }
}