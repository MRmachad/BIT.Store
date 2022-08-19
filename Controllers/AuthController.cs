using BIT.Identidade.API.Extensions;
using BIT.Identidade.API.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;


namespace BIT.Identidade.API.Controllers
{
    //api/[controller]/nova-Conta
    //api/[controller]/autenticar
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : MainController
    {
        private readonly SignInManager<IdentityUser> signInManager;
        private readonly UserManager<IdentityUser> userManager;
        private readonly AppSettings appSettings;
        public AuthController(SignInManager<IdentityUser> signInManager,
                                            UserManager<IdentityUser> userManager,
                                            IOptions<AppSettings> appSettings)
        {
            this.signInManager = signInManager;
            this.userManager = userManager;
            this.appSettings = appSettings.Value;
        }

        [HttpPost("nova-Conta")]
        public async Task<IActionResult> Registrar(UsuarioRegistroViewModel usuarioRegistro)
        {
            if (!ModelState.IsValid) return CustomResponse(ModelState);

            var user = new IdentityUser
            {
                Email = usuarioRegistro.Email,
                UserName = usuarioRegistro.Email,
                EmailConfirmed = true
            };

            //O identity so aceita senhas fortes @Ba67678
            var result = await this.userManager.CreateAsync(user, usuarioRegistro.Senha);

            if (result.Succeeded)
            {

                ////ispersistent = ser lembrado
                //await this.signInManager.SignInAsync(user, isPersistent: false);

                return CustomResponse(await GerarJwt(usuarioRegistro.Email));
            }
            else
            {
                foreach (IdentityError error in result.Errors)
                {
                    AdicionarErro(error.Description);
                }
                return CustomResponse();
            }


        }

        [HttpPost("autenticar")]
        public async Task<ActionResult> Login(UsuarioLoginViewModel usuarioLogin)
        {
            if (!ModelState.IsValid) return CustomResponse();

            //Aqui logamos conforme a senha
            var result = await this.signInManager.PasswordSignInAsync(usuarioLogin.Email,
                                                                      usuarioLogin.Senha,
                                                                      isPersistent: false,
                                                                      lockoutOnFailure: true);

            if (result.Succeeded) return CustomResponse(await GerarJwt(usuarioLogin.Email));

            if (result.IsLockedOut)
            {
                AdicionarErro("Usuario bloaqueado temporariamente por tentantivas invalidadas");
                return CustomResponse();
            }
            AdicionarErro("Usuario ou senha incorreta");
            return CustomResponse();
        }

        public async Task<UsuarioRespostaLoginViewModel> GerarJwt(string email)
        {
            var user = await this.userManager.FindByEmailAsync(email);
            var claims = await this.userManager.GetClaimsAsync(user);
            var userRoles = await this.userManager.GetRolesAsync(user);

            claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
            claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Nbf, ToUnixEpochDate(DateTime.UtcNow).ToString()));
            claims.Add(new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(DateTime.UtcNow).ToString(), ClaimValueTypes.Integer64));

            foreach (var userRole in userRoles)
            {
                claims.Add(new Claim("role", userRole));
            }

            var identityClaims = new ClaimsIdentity();
            identityClaims.AddClaims(claims);

            var tokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.ASCII.GetBytes(this.appSettings.Secret);

            //criação de fato do token
            var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
            {
                Issuer = this.appSettings.Emissor,
                Audience = this.appSettings.ValidoEm,
                Subject = identityClaims,
                Expires = DateTime.UtcNow.AddHours(this.appSettings.ExpiracaoHoras),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            });

            var encodedToken = tokenHandler.WriteToken(token);

            var response = new UsuarioRespostaLoginViewModel
            {
                AccessToken = encodedToken,
                ExpiresIn = TimeSpan.FromHours(this.appSettings.ExpiracaoHoras).TotalSeconds,
                UsuarioToken = new UsuarioToken
                {
                    Id = user.Id,
                    Email = user.Email,
                    Claims = claims.Select(c => new UsuarioClaim { Type = c.Type, Value = c.Value })
                }
            };

            return response;
        }

        private static long ToUnixEpochDate(DateTime date)
            => (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1910, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
    }
}
