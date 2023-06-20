using System.Diagnostics;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.Identity.Web;
using OpenTelemetry;
using OpenTelemetry.Context.Propagation;

public class OIDCTracePropagator : TraceContextPropagator
{
    private readonly IOptionsMonitor<OpenIdConnectOptions> _options;

    private readonly TraceContextPropagator _internalPropagator = new();

    public OIDCTracePropagator(IOptionsMonitor<MicrosoftIdentityOptions> options)
    {
        _options = options;
    }

    public override PropagationContext Extract<T>(PropagationContext currentContext, T carrier, Func<T, string, IEnumerable<string>> getter)
    {
        var baseContext = base.Extract(currentContext, carrier, getter);
        if (baseContext.ActivityContext.IsValid())
            return baseContext;

        if (carrier is HttpRequest request &&
            request.Path.HasValue &&
            request.Path.Value == "/signin-oidc")
        {
            var form = request.ReadFormAsync().GetAwaiter().GetResult();

            var unProtectedState = _options.Get(OpenIdConnectDefaults.AuthenticationScheme)
                .StateDataFormat.Unprotect(form["state"]);
            if (unProtectedState == null)
                return currentContext;

            var contextFromAuthProperties = _internalPropagator.Extract(
                currentContext,
                unProtectedState.Items,
                (dictionaryOfStateValues, keyToFind) =>
                {
                    return dictionaryOfStateValues.ContainsKey(keyToFind) ?
                        new List<string> { dictionaryOfStateValues[keyToFind]! } :
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
    internal static void AddTraceContextToAuthenticationProperties(RedirectContext context)
    {
        Propagators.DefaultTextMapPropagator.Inject(
            new PropagationContext(Activity.Current?.Context ?? new ActivityContext(), Baggage.Current),
            context.Properties.Items,
            AddItemToDictionary);
    }



    private static void AddItemToDictionary(IDictionary<string, string?> dictionary, string key, string value)
    {
        if (!dictionary.ContainsKey(key))
        {
            dictionary.Add(key, value);
        }
    }

}


public class OIDCBaggagePropagator : BaggagePropagator
{
    private readonly IOptionsMonitor<OpenIdConnectOptions> _options;

    private readonly BaggagePropagator _internalPropagator = new();

    public OIDCBaggagePropagator(IOptionsMonitor<MicrosoftIdentityOptions> options)
    {
        _options = options;
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

            var unprotectedState = _options.Get(OpenIdConnectDefaults.AuthenticationScheme)
                .StateDataFormat.Unprotect(form["state"]);
            if (unprotectedState == null)
            {
                return currentContext;
            }

            var contextFromAuthProperties = _internalPropagator.Extract(
                currentContext,
                unprotectedState.Items,
                (dictionaryOfStateValues, keyToFind) =>
                {
                    return dictionaryOfStateValues.ContainsKey(keyToFind) ?
                        new List<string> { dictionaryOfStateValues[keyToFind]! } :
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
