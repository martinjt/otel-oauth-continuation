using System.Diagnostics;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using OpenTelemetry;
using OpenTelemetry.Context.Propagation;

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
            return baseContext;

        if (carrier is HttpRequest request &&
            request.Path.HasValue &&
            request.Path.Value == "/signin-oidc")
        {
            var form = request.ReadFormAsync().GetAwaiter().GetResult();
            var dataFormat = new PropertiesDataFormat(_dataProtector);

            var unprotectedState = dataFormat.Unprotect(form["state"]);
            if (unprotectedState == null)
                return currentContext;

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
    private readonly IDataProtector _dataProtector;
    private readonly BaggagePropagator _internalPropagator = new();

    public OIDCBaggagePropagator(IDataProtector dataProtector)
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
