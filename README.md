# .NET OAuth with OpenTelemetry Trace Propagation

This is an example of how to make an OAuth flow be a single trace using a custom trace Propagation handler.

This is the setup guide used for the application: https://learn.microsoft.com/en-us/aspnet/core/security/authentication/azure-ad-b2c?view=aspnetcore-7.0

## Create Azure B2C tenant

Make sure to setup a User Policy with the name `signup_signin`

## Setup App Registration in Azure

https://learn.microsoft.com/en-us/azure/active-directory-b2c/tutorial-register-applications?tabs=app-reg-ga#register-a-web-application

## Adding the Microsoft Identity Packages

dotnet add package Microsoft.Identity.Web
dotnet add package Microsoft.Identity.Web.UI

## Running the application

dotnet run --launch-profile https