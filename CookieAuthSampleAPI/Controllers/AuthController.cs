using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using CookieAuthSampleAPI.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace CookieAuthSampleAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly UserManager<IdentityUser> userManager;

        public AuthController(SignInManager<IdentityUser> signInManager, UserManager<IdentityUser> userManager)
        {
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody]RegisterInfo info)
        {
            if (info == null || string.IsNullOrEmpty(info.Username) || string.IsNullOrEmpty(info.Password))
            {
                return BadRequest();
            }

            await userManager.CreateAsync(new IdentityUser()
            {
                Email = info.Email,
                EmailConfirmed = true,
                UserName = info.Username,
            }, info.Password);

            return Ok();
        }

        [HttpPost]
        public async Task<IActionResult> Logout()
        {
            await Request.HttpContext.SignOutAsync();
            return Ok();
        }

        [HttpPost]
        public async Task<IActionResult> Login([FromBody]LoginInfo info)
        {
            if (info == null || string.IsNullOrEmpty(info.Username) || string.IsNullOrEmpty(info.Password))
            {
                return BadRequest();
            }

            var user = await userManager.FindByNameAsync(info.Username);
            if (user == null)
            {
                return BadRequest();
            }

            var claimsIdentity = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.Email, user.Email)
            }, "Cookies");

            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);
            await Request.HttpContext.SignInAsync("Cookies", claimsPrincipal);
            return Ok();
        }
    }
}