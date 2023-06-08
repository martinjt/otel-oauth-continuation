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
        //  .AddOtlpExporter(opt => {
        //     opt.Endpoint = new Uri("https://api.honeycomb.io:443/v1/traces");
        //     opt.Headers = string.Join(",", new List<string>
        //     {
        //         $"x-otlp-version=0.16.0",
        //         $"x-honeycomb-team={builder.Configuration.GetValue<string>("Honeycomb:ApiKey")}",
        //     });
        //  })
         .AddHoneycomb(builder.Configuration)
         .AddConsoleExporter();
    });

var dataProtector = DataProtectionProvider.Create("armadillo").CreateProtector("garden");

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
        .AddMicrosoftIdentityWebApp(i =>
        {
            builder.Configuration.GetSection("AzureADB2C").Bind(i);
            i.StateDataFormat = new PropertiesDataFormat(dataProtector);
            i.Events.OnRedirectToIdentityProvider = context =>
            {
                Propagators.DefaultTextMapPropagator.Inject(
                    new PropagationContext(Activity.Current?.Context ?? new ActivityContext(), Baggage.Current),
                    context.Properties.Items, (objectToAddTo, keyToSet, valueToSetTo) =>
                    {
                        objectToAddTo.Add(keyToSet, valueToSetTo);
                    });

                return Task.CompletedTask;
            };
        });

builder.Services.AddAuthorization(options =>
{
    // By default, all incoming requests will be authorized according to 
    // the default policy
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

public class OIDCTracePropagator : TraceContextPropagator
{
    private readonly IDataProtector _dataProtector;
    private readonly TraceContextPropagator _internalPropagator = new();

    public OIDCTracePropagator(IDataProtector dataProtector)
    {
        _dataProtector = dataProtector;
    }

    public override PropagationContext Extract<T>(PropagationContext currentContext, T carrier, Func<T, string, IEnumerable<string>> getter)
    {
        var baseContext = base.Extract(currentContext, carrier, getter);
        if (baseContext.ActivityContext.IsValid())
        {
            return baseContext;
        }

        if (carrier is HttpRequest request &&
            request.Path.HasValue &&
            request.Path.Value == "/signin-oidc")
        {
            var form = request.ReadFormAsync().GetAwaiter().GetResult();
            var dataFormat = new PropertiesDataFormat(_dataProtector);

            var unprotectedState = dataFormat.Unprotect(form["state"]);

            var contextFromAuthProperties = _internalPropagator.Extract(
                currentContext,
                unprotectedState.Items,
                (dictionaryOfStateValues, keyToFind) =>
                {
                    return dictionaryOfStateValues.ContainsKey(keyToFind) ?
                        new List<string> { dictionaryOfStateValues[keyToFind] } :
                        Enumerable.Empty<string>();
                });

            return new PropagationContext(
                contextFromAuthProperties.ActivityContext, contextFromAuthProperties.Baggage);
        }
        return currentContext;
    }

    public override void Inject<T>(PropagationContext context, T carrier, Action<T, string, string> setter)
    {
        _internalPropagator.Inject(context, carrier, setter);
    }

}
