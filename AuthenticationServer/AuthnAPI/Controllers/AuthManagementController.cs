using AuthnAPI.Configuration;
using AuthnAPI.Models.DTO.Responses;
using AuthnAPI.Models.DTO.Requests;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using AuthnAPI.Data;
using AuthnAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace AuthnAPI.Controllers
{
    [Route("api/[controller]")] // api/authManagement
    [ApiController]
    public class AuthManagementController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;

        private readonly JwtConfig _jwtConfig;

        private readonly TokenValidationParameters _tokenValidationParams;

        private readonly ApiDbContext _apiDbContext;

        public AuthManagementController(
            UserManager<IdentityUser> userManager,
            IOptionsMonitor<JwtConfig> optionsMonitor,
            TokenValidationParameters tokenValidationParams,
            ApiDbContext apiDbContext)
        {
            _userManager = userManager;
            _jwtConfig = optionsMonitor.CurrentValue;
            _tokenValidationParams = tokenValidationParams;
            _apiDbContext = apiDbContext;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationDto user)
        {
            if (ModelState.IsValid)
            {
                // We can utilize model
                var existingUser = await _userManager.FindByEmailAsync(user.Email); //there can only be one user with that email in the system
                
                if(existingUser != null)
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Errors = new List<string>()
                        {
                            "Email already in use"
                        },
                        Success = false
                    });
                }

                var newUser =  new IdentityUser() { Email = user.Email, UserName = user.Username };
                var isCreated = await _userManager.CreateAsync(newUser, user.Password);
                if (isCreated.Succeeded)
                {
                    var jwtToken = await GenerateJwtToken(newUser);
                    return Ok(jwtToken);
                } else
                {
                    return BadRequest(new RegistrationResponse()
                    {
                        Errors = isCreated.Errors.Select(x => x.Description).ToList(),
                        Success = false
                    });
                }

            }

            return BadRequest(new RegistrationResponse() { 
                Errors = new List<string>()
                {
                    "Invalid payload"
                },
                Success = false
            });
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequest user)
        {

            if (ModelState.IsValid)
            {
                var existingUser = await _userManager.FindByEmailAsync(user.Email);

                if(existingUser == null) {
                        return BadRequest(new RegistrationResponse() {
                            Errors = new List<string>() {
                                "Invalid login request"
                            },
                                Success = false
                        });
                }

                var isCorrect = await _userManager.CheckPasswordAsync(existingUser, user.Password);

                if (!isCorrect)
                {
                    return BadRequest(new RegistrationResponse() {
                        Errors = new List<string>() {
                                "Invalid login request"
                            },
                        Success = false
                    });
                }

                var jwtToken = await GenerateJwtToken(existingUser);

                return Ok(jwtToken);
            }


            return BadRequest(new RegistrationResponse()
            {
                Errors = new List<string>()
                {
                    "Invalid payload"
                },
                Success = false
            });


        }

        [HttpPost]
        [Route("RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
        {
            if (ModelState.IsValid)
            {
                var result = await VerifyandGenerateToken(tokenRequest);

                if(result == null)
                {
                    return BadRequest(new RegistrationResponse() {
                        Errors = new List<string>() {
                            "Invalid tokens"
                        },
                        Success = false
                    });
                }

                return Ok(result);

            }
            return BadRequest(new RegistrationResponse() {
                Errors = new List<string>() {
                    "Invalid Payload"
                },
                Success = false
            });
        }

        
        private async Task<AuthResult> VerifyandGenerateToken(TokenRequest tokenRequest)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            try
            {   
                //validation 1 - check if it is a jwttoken format in our program via tokenValidationParams
                var tokenInVerification = jwtTokenHandler.ValidateToken(tokenRequest.Token, _tokenValidationParams, out var validatedToken);

                //validation 2 - check using the security algorithm selected , it's encryption
                if(validatedToken is JwtSecurityToken jwtSecurityToken)
                {
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCulture);

                    if(result == false)
                    {
                        return null;
                    }
                }

                //validation 3 - check if the token is not yet expired
                var utcExpiryDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

                var expiryDate = UnixTimeStampToDateTime(utcExpiryDate);

                if(expiryDate > DateTime.UtcNow)
                {
                    return new AuthResult() {
                        Success = false,
                        Errors = new List<string>() {
                            "Token has not yet expired"
                        }
                    };
                }

                //validation 4 - check against api dbcontext if it exists within the database of the token
                var storedToken = await _apiDbContext.RefreshTokens.FirstOrDefaultAsync(x => x.Token == tokenRequest.RefreshToken);

                if(storedToken == null)
                {
                    return new AuthResult() {
                        Success = false,
                        Errors = new List<string>() {
                            "Token does not exist"
                        }
                    };
                }

                //validation 5 - check to see if the token has already been used 
                if (storedToken.IsUsed)
                {
                    return new AuthResult() {
                        Success = false,
                        Errors = new List<string>() {
                            "Token has been used"
                        }
                    };
                }

                //validation 6 - check if the token has been revoked or not
                if (storedToken.IsRevoked)
                {
                    return new AuthResult() {
                        Success = false,
                        Errors = new List<string>() {
                            "Token has been revoked"
                        }
                    };
                }

                //validation 7 - check jti matches the id of the refresh token
                var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

                if(storedToken.JwtId != jti)
                {
                    return new AuthResult() {
                        Success = false,
                        Errors = new List<string>() {
                            "Token doesn't match"
                        }
                    };
                }

                // update current token

                storedToken.IsUsed = true;
                _apiDbContext.RefreshTokens.Update(storedToken);
                await _apiDbContext.SaveChangesAsync();

                //generate a new token
                var dbUser = await _userManager.FindByIdAsync(storedToken.UserId);
                return await GenerateJwtToken(dbUser);


            }
            catch (Exception ex)
            {
                return null;
            }

        }

        private DateTime UnixTimeStampToDateTime(long unixTimeStamp)
        {
            var dateTimeVal = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            dateTimeVal = dateTimeVal.AddSeconds(unixTimeStamp).ToUniversalTime();
            return dateTimeVal;
        }


        private async Task<AuthResult> GenerateJwtToken(IdentityUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_jwtConfig.Secret);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim ("Id", user.Id),
                    new Claim (JwtRegisteredClaimNames.Email, user.Email),
                    new Claim (JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim (JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                }),
                Expires = DateTime.UtcNow.AddHours(24), // 5-10 minutes is actual/ideal - use this to test if expiry validations work
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            var refreshToken = new RefreshToken() {
                JwtId = token.Id,
                IsUsed = false,
                IsRevoked = false,
                UserId = user.Id,
                AddedDate = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddMonths(6),
                Token = RandomString(35) + Guid.NewGuid()
            };

            await _apiDbContext.RefreshTokens.AddAsync(refreshToken);
            await _apiDbContext.SaveChangesAsync();

            return new AuthResult() {
                Token = jwtToken,
                Success = true,
                RefreshToken = refreshToken.Token
            };
        }

        private string RandomString (int length)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

            return new string(Enumerable.Repeat(chars, length)
                .Select(x => x[random.Next(x.Length)]).ToArray());
        }

        [HttpPost]
        [Route("jwtdecode")]
        public async Task<IActionResult> DecodeJwt([FromBody] string jwtstring)
        {

            var bytes = Convert.FromBase64String(jwtstring);
            return Ok(Encoding.UTF8.GetString(bytes));
     
        }





    }
}
