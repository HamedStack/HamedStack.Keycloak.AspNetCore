// ReSharper disable IdentifierTypo
// ReSharper disable UnusedMember.Global
// ReSharper disable ClassNeverInstantiated.Global
// ReSharper disable AutoPropertyCanBeMadeGetOnly.Global

namespace HamedStack.Keycloak.AspNetCore;

/// <summary>
/// Provides configuration options for integrating with Keycloak for authentication and authorization.
/// </summary>
/// <remarks>
/// This configuration is essential for setting up OpenID Connect with Keycloak.
/// </remarks>
/// <example>
/// Here's how you can use the <see cref="KeycloakOptions"/>:
/// <code>
/// var options = new KeycloakOptions
/// {
///     Authority = "https://keycloak.example.com/auth/realms/myrealm",
///     ClientId = "my-client-id",
///     ClientSecret = "my-client-secret"
/// };
/// </code>
/// </example>
public class KeycloakOptions
{
    /// <summary>
    /// Gets or sets the Keycloak authority URL.
    /// </summary>
    /// <remarks>
    /// This is the URL of the Keycloak server's realm where your client is defined.
    /// Typically, it's in the format "https://[keycloak-domain]/auth/realms/[realm-name]".
    /// </remarks>
    /// <example>
    /// <code>
    /// options.Authority = "https://keycloak.example.com/auth/realms/myrealm";
    /// </code>
    /// </example>
    public string Authority { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the client ID used for authentication with Keycloak.
    /// </summary>
    /// <remarks>
    /// This is the client identifier registered in your Keycloak realm.
    /// </remarks>
    /// <example>
    /// <code>
    /// options.ClientId = "my-client-id";
    /// </code>
    /// </example>
    public string ClientId { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the client secret used for authentication with Keycloak.
    /// </summary>
    /// <remarks>
    /// This is the secret associated with your client in Keycloak. It's used in confidential client types.
    /// </remarks>
    /// <example>
    /// <code>
    /// options.ClientSecret = "my-client-secret";
    /// </code>
    /// </example>
    public string ClientSecret { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets whether HTTPS is mandatory for metadata retrieval from Keycloak.
    /// </summary>
    /// <remarks>
    /// It's recommended to always use HTTPS in production setups for security.
    /// </remarks>
    /// <example>
    /// <code>
    /// options.RequireHttpsMetadata = true;
    /// </code>
    /// </example>
    public bool RequireHttpsMetadata { get; set; } = true;

    /// <summary>
    /// Gets or sets the default redirect URI after authentication.
    /// </summary>
    /// <remarks>
    /// This is where Keycloak will redirect the user after a successful authentication.
    /// </remarks>
    /// <example>
    /// <code>
    /// options.DefaultRedirectUri = "/home";
    /// </code>
    /// </example>
    public string DefaultRedirectUri { get; set; } = "/";

    /// <summary>
    /// Gets or sets whether the token issuer should be validated.
    /// </summary>
    /// <remarks>
    /// It's a best practice to validate the issuer to ensure the token was issued by a trusted Identity provider like Keycloak.
    /// </remarks>
    /// <example>
    /// <code>
    /// options.ValidateIssuer = true;
    /// </code>
    /// </example>
    public bool ValidateIssuer { get; set; } = true;

    /// <summary>
    /// Gets or sets the valid issuer for token validation.
    /// </summary>
    /// <remarks>
    /// This should match the issuer claim in the token from Keycloak.
    /// </remarks>
    /// <example>
    /// <code>
    /// options.ValidIssuer = "https://keycloak.example.com/auth/realms/myrealm";
    /// </code>
    /// </example>
    public string? ValidIssuer { get; set; }

    /// <summary>
    /// Gets or sets the valid audiences for token validation.
    /// </summary>
    /// <remarks>
    /// This ensures the token was intended for the correct audience, often the application itself.
    /// </remarks>
    /// <example>
    /// <code>
    /// options.ValidAudiences = new[] { "my-client-id" };
    /// </code>
    /// </example>
    public IEnumerable<string>? ValidAudiences { get; set; }

    /// <summary>
    /// Gets or sets whether the token lifetime should be validated.
    /// </summary>
    /// <remarks>
    /// Validating the token's lifetime ensures that it hasn't expired and is still valid for use.
    /// </remarks>
    /// <example>
    /// <code>
    /// options.ValidateLifetime = true;
    /// </code>
    /// </example>
    public bool ValidateLifetime { get; set; } = true;
}
