// ReSharper disable UnusedType.Global
// ReSharper disable InconsistentNaming
// ReSharper disable IdentifierTypo
// ReSharper disable UnusedMember.Global

using IdentityModel;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace HamedStack.Keycloak.AspNetCore;

/// <summary>
/// Provides extension methods for integrating Keycloak authentication and authorization with the provided services.
/// </summary>
/// <remarks>
/// This service collection simplifies the configuration for using Keycloak as an OpenID Connect Identity provider.
/// </remarks>
public static class KeycloakServiceCollection
{
    private const string CODE_RESPONSE_TYPE = "code";

    /// <summary>
    /// Adds and configures Keycloak authentication using OpenID Connect and JWT Bearer token validation.
    /// </summary>
    /// <param name="services">The service collection to add the authentication services to.</param>
    /// <param name="keycloakOptions">Configuration options for the Keycloak integration.</param>
    /// <param name="httpClientFactory">Factory to create instances of <see cref="System.Net.Http.HttpClient"/>.</param>
    /// <returns>The same service collection so that multiple calls can be chained.</returns>
    /// <remarks>
    /// This method configures the OpenID Connect handler for the application to integrate with Keycloak.
    /// It handles the OpenID Connect Code flow, token validation, and sets up JWT Bearer token authentication.
    /// </remarks>
    /// <example>
    /// <code>
    /// var keycloakOptions = new KeycloakOptions
    /// {
    ///     Authority = "https://keycloak.example.com/auth/realms/myrealm",
    ///     ClientId = "my-client-id",
    ///     ClientSecret = "my-client-secret"
    /// };
    ///
    /// services.AddKeycloakAuthentication(keycloakOptions, httpClientFactory);
    /// </code>
    /// </example>
    public static IServiceCollection AddKeycloakAuthentication(this IServiceCollection services, KeycloakOptions keycloakOptions, IHttpClientFactory httpClientFactory)
    {
        services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddOpenIdConnect(options =>
            {
                options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.Authority = keycloakOptions.Authority;
                options.RequireHttpsMetadata = keycloakOptions.RequireHttpsMetadata;
                options.ClientId = keycloakOptions.ClientId;
                options.ResponseType = CODE_RESPONSE_TYPE;
                options.SaveTokens = true;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.TokenValidationParameters.ValidIssuer = keycloakOptions.ValidIssuer;
                options.TokenValidationParameters.ValidateIssuer = keycloakOptions.ValidateIssuer;
                options.TokenValidationParameters.ValidAudiences = keycloakOptions.ValidAudiences;
                options.TokenValidationParameters.ValidateLifetime = keycloakOptions.ValidateLifetime;
                options.Events = new OpenIdConnectEvents
                {
                    OnAuthorizationCodeReceived = async context =>
                    {
                        var httpClient = httpClientFactory.CreateClient();
                        var discoveryResponse = await httpClient.GetDiscoveryDocumentAsync(context.Options.Authority);

                        if (discoveryResponse.IsError)
                        {
                            throw new Exception("Error in discovery document", discoveryResponse.Exception);
                        }

                        var tokenResponse = await httpClient.RequestTokenAsync(new TokenRequest
                        {
                            Address = discoveryResponse.TokenEndpoint,
                            GrantType = OidcConstants.GrantTypes.RefreshToken,
                            ClientId = keycloakOptions.ClientId,
                            ClientSecret = keycloakOptions.ClientSecret,
                            Parameters =
                            {
                                { OidcConstants.TokenRequest.RefreshToken, context.ProtocolMessage.RefreshToken }
                            }
                        });

                        if (tokenResponse.IsError)
                        {
                            throw new Exception("Error refreshing token", tokenResponse.Exception);
                        }

                        if (tokenResponse is { AccessToken: not null, RefreshToken: not null })
                            context.HandleCodeRedemption(tokenResponse.AccessToken, tokenResponse.RefreshToken);
                    }
                };
            })
            .AddJwtBearer(options =>
            {
                options.Authority = keycloakOptions.Authority;
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = keycloakOptions.ValidateIssuer,
                    ValidIssuer = keycloakOptions.ValidIssuer,
                    ValidateAudience = keycloakOptions.ValidAudiences != null,
                    ValidAudiences = keycloakOptions.ValidAudiences,
                    ValidateLifetime = keycloakOptions.ValidateLifetime
                };
            });

        return services;
    }
}