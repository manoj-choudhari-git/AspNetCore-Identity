using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace JwtAuthRefreshTokenSampleAPI.Data
{
    public class ApplicationUser: IdentityUser
    {
        public List<RefreshToken> RefreshTokens { get; set; }
    }
}
