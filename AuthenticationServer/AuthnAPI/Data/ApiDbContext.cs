using AuthnAPI.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthnAPI.Data
{
    public class ApiDbContext : IdentityDbContext
    {
        public virtual DbSet<ItemData> Items { get; set; }

        public virtual DbSet<RefreshToken> RefreshTokens { get; set; }

        public ApiDbContext(DbContextOptions<ApiDbContext> options)
            :base(options)
        {

        }




    }
}
