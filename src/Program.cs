using System.Diagnostics;
using System.Text;
using Google.Protobuf.WellKnownTypes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;
using Microsoft.IdentityModel.Tokens;
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
        b.ConfigureResource(r => r.AddService("oauth-application"))
         .AddAspNetCoreInstrumentation()
         .AddHoneycomb(builder.Configuration);
    });


var dataProtector = DataProtectionProvider.Create("my provider").CreateProtector("mypurpose");

builder.Services.ConfigureOpenTelemetryTracerProvider((sp, tp) =>
{
    Sdk.SetDefaultTextMapPropagator(new CompositeTextMapPropagator(
        new List<TextMapPropagator>() {
            new OIDCTracePropagator(dataProtector)
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
                context.ProtocolMessage.State = "This is the user state";

                Propagators.DefaultTextMapPropagator.Inject(
                    new PropagationContext(Activity.Current?.Context ?? new ActivityContext(), Baggage.Current), 
                    context.Properties.Items, (items, key, value) => {
                        items.Add(key, value);
                    });
                Console.WriteLine($"Original TraceId: {Activity.Current.TraceId.ToString()}");

                return Task.CompletedTask;
            };
            i.Events.OnTokenValidated = context =>
            {
                Console.WriteLine($"State Parameter was: {context.ProtocolMessage.State}");
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

    public OIDCTracePropagator(IDataProtector dataProtector)
    {
        _dataProtector = dataProtector;
    }

    public override PropagationContext Extract<T>(PropagationContext context, T carrier, Func<T, string, IEnumerable<string>> getter)
    {

        var request = carrier as HttpRequest;
        if (request != null &&
            request.Path.HasValue &&
            request.Path.Value == "/signin-oidc")
        {
            var form = request.ReadFormAsync().GetAwaiter().GetResult();
            var dataFormat = new PropertiesDataFormat(_dataProtector);
            
            var unprotectedState = dataFormat.Unprotect(form["state"]);
            context = Propagators.DefaultTextMapPropagator.Extract(
                context,
                unprotectedState.Items,
                (items, key) => {
                    return items.ContainsKey(key) ? 
                        new List<string> { items[key] } :
                        Enumerable.Empty<string>();
                });

            Console.WriteLine($"New TraceId: {context.ActivityContext.TraceId.ToString()}");

            return context;
        }
        return base.Extract<T>(context, carrier, getter);
    }

    public override void Inject<T>(PropagationContext context, T carrier, Action<T, string, string> setter)
    {
        base.Inject(context, carrier, setter);
    }

}
