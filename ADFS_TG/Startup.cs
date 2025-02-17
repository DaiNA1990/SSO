using ADFS_TG.Ultility;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.OpenApi.Models;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;

namespace ADFS_TG
{
    public class Startup
    {
        public const string COOKIE_NAME = "UserCookie";
        public const string SESSION_NAME = "UserSession";
        public const string SECURE_COOKIE = "CookieAuthentication";
        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
            services.AddCors();
            services.AddDistributedMemoryCache();
            services.AddMemoryCache();
            services.AddSession(conf =>
            {
                //conf.IdleTimeout = new TimeSpan(0, int.Parse(ConfigurationManager.AppSetting["TokenSetting:AccessExpiration"]), 0);
                conf.Cookie.HttpOnly = true;
                conf.Cookie.SameSite = SameSiteMode.None;
                conf.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                conf.Cookie.Name = SESSION_NAME;
            });

            services.ConfigureApplicationCookie(options =>
            {
                options.Cookie.HttpOnly = true;
                options.Cookie.Name = COOKIE_NAME;
                options.Cookie.SameSite = SameSiteMode.None;
                options.ExpireTimeSpan = TimeSpan.FromHours(1);
                options.SlidingExpiration = true;
            });

            services.AddAuthentication(SECURE_COOKIE)
                 .AddCookie(SECURE_COOKIE, config =>
                 {
                     config.Cookie.Name = COOKIE_NAME; // Name of cookie
                     config.Cookie.SameSite = SameSiteMode.None;
                     config.Cookie.HttpOnly = true;
                     config.ExpireTimeSpan = TimeSpan.FromHours(1);
                 }).AddCookie(SESSION_NAME, config =>
                 {
                     config.Cookie.Name = SESSION_NAME; // Name of cookie
                     config.Cookie.SameSite = SameSiteMode.None;
                     config.Cookie.HttpOnly = true;
                     //config.ExpireTimeSpan = new TimeSpan(0, int.Parse(ConfigurationManager.AppSetting["TokenSetting:AccessExpiration"]), 0);
                 });
            services.AddControllers(options => {
            }).AddNewtonsoftJson(options => {
                options.SerializerSettings.ReferenceLoopHandling = ReferenceLoopHandling.Ignore;
            }).SetCompatibilityVersion(CompatibilityVersion.Latest);
            services.AddAuthorization();
            //Register the Swagger generator, defining 1 or more Swagger documents
            services.AddSwaggerGen(c => {
                c.SwaggerDoc("v1.0", new OpenApiInfo
                {
                    Version = ConfigurationManager.AppSetting["Swagger:Version"],
                    Contact = new OpenApiContact
                    {
                        Name = ConfigurationManager.AppSetting["Swagger:Name"],
                        Url = new Uri(ConfigurationManager.AppSetting["Swagger:Url"])
                    }
                });

                //Set the comments path for the Swagger JSON and UI.
                //var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                //var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                //c.IncludeXmlComments(xmlPath);
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILoggerFactory loggerFactory)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseRouting();
            app.UseSwagger();
            app.UseSwaggerUI(c => {
                c.SwaggerEndpoint(ConfigurationManager.AppSetting["Swagger:Endpoint"], ConfigurationManager.AppSetting["Swagger:EndpointName"]);
            });

            app.UseCors(builder => builder
                .AllowAnyOrigin()
                .AllowAnyHeader()
                .AllowAnyMethod()
                //.AllowCredentials()
            );
            loggerFactory.AddLog4Net();
            app.UseHttpsRedirection();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseSession();

            app.UseEndpoints(endpoints => {
                endpoints.MapControllers();
            });
        }
    }
}
