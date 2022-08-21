using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace BIT.Identidade.API.Configuration
{
    public static class ApiConfiguration
    {
        public static IServiceCollection AddApiConfiguration(this IServiceCollection services)
        {
            //Adiciona suporte ao web API
            services.AddControllers();
            services.AddEndpointsApiExplorer();
            return services;
        }
        
        public static IApplicationBuilder UseApiConfiguration(this IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseIdentityConfiguration();

            app.UseRouting();

            /* Seta o esquema de rotas e Varre todas as classe que herdam da interface controler criando um caminho de rota (endpoint)*/
            app.UseEndpoints(endpoint =>
            {
                endpoint.MapControllers();
            });

            return app;


        }
    }

}
