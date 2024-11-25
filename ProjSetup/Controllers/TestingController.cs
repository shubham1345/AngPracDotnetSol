using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace ProjSetup.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize]
    public class TestingController : ControllerBase
    {
        [HttpGet("Info")]        
        public IActionResult Info()
        {
            return Ok("return");
        }
    }
}
