using System.Diagnostics;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using OpenTelemetry;
using OpenTelemetry.Context.Propagation;
using OpenTelemetry.Resources;
using OpenTelemetry.Trace;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddOpenTelemetry()
    .ConfigureResource(r => r.AddService("oauth-application"))
    .WithTracing(b =>
    {
        b
         .AddAspNetCoreInstrumentation()
         .SetSampler(new AlwaysOnSampler())
         .AddHoneycomb(builder.Configuration)
         .AddConsoleExporter();
    });

var dataProtector = DataProtectionProvider.Create("oidc").CreateProtector("state-encryption");

builder.Services.ConfigureOpenTelemetryTracerProvider((sp, tp) =>
{
    Sdk.SetDefaultTextMapPropagator(new CompositeTextMapPropagator(
        new List<TextMapPropagator>() {
            new OIDCTracePropagator(dataProtector),
            new BaggagePropagator()
        }));
});


builder.Services.AddRazorPages()
    .AddMicrosoftIdentityUI();

builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp((Action<MicrosoftIdentityOptions>)(i =>
    {
        builder.Configuration.GetSection("AzureADB2C").Bind(i);
        i.StateDataFormat = new PropertiesDataFormat(dataProtector);
        i.Events.OnRedirectToIdentityProvider = context =>
        {
            OIDCTracePropagator.AddTraceContextToAuthenticationProperties(context);

            return Task.CompletedTask;
        };
    }));



builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = options.DefaultPolicy;
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .AllowAnonymous();

app.Run();
