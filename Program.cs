using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

IdentityModelEventSource.ShowPII = true;
IdentityModelEventSource.LogCompleteSecurityArtifact = true;

static NoopCredentials CreateNoOpCredential()
{
    return new NoopCredentials();
}

static KeyClientOptions CreateKeyClientOption()
{
    return GetClientOptions(new KeyClientOptions(KeyClientOptions.ServiceVersion.V7_4)
    {
        DisableChallengeResourceVerification = true,
        RetryPolicy = new RetryPolicy(0, DelayStrategy.CreateFixedDelayStrategy(TimeSpan.Zero))
    });
}

static CryptographyClientOptions CryptographyClientOption()
{
    return GetClientOptions(new CryptographyClientOptions(CryptographyClientOptions.ServiceVersion.V7_4)
    {
        DisableChallengeResourceVerification = true,
        RetryPolicy = new RetryPolicy(0, DelayStrategy.CreateFixedDelayStrategy(TimeSpan.Zero))
    });
}


static T GetClientOptions<T>(T options) where T : ClientOptions
{
    DisableSslValidationOnClientOptions(options);
    return options;
}

/// <summary>
/// Disables server certification callback.
/// <br/>
/// <b>WARNING: Do not use in production environments.</b>
/// </summary>
/// <param name="options"></param>
static void DisableSslValidationOnClientOptions(ClientOptions options)
{
    options.Transport = new HttpClientTransport(CreateHttpClientHandlerWithDisabledSslValidation());
}

static HttpClientHandler CreateHttpClientHandlerWithDisabledSslValidation()
{
    return new HttpClientHandler { ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator };
}


string keyVaultUrl = "https://127.0.0.1:8443/";
string keyName = "your-key-name";

var rsaKeyOptions = new CreateRsaKeyOptions(keyName, hardwareProtected: false)
{
    KeySize = 2048,
    Exportable = true,
    Enabled = true,
    KeyOperations = { KeyOperation.Sign, KeyOperation.Verify }
};

var credential = CreateNoOpCredential();
var keyClientOption = CreateKeyClientOption();
var cryptographicClientOption = CryptographyClientOption();
var keyClient = new KeyClient(new Uri(keyVaultUrl), credential, keyClientOption);

try
{
    // Create the key
    KeyVaultKey key = await keyClient.CreateKeyAsync(keyName, rsaKeyOptions.KeyType, rsaKeyOptions);

    // Generate a new RSA key pair
    RSA rsaKey = RSA.Create(2048);

    var rsaParams = rsaKey.ExportParameters(true);

    var jsonWebKey = new Azure.Security.KeyVault.Keys.JsonWebKey([KeyOperation.Sign, KeyOperation.Verify])
    {
        KeyType = KeyType.Rsa,
        N = rsaParams.Modulus,
        E = rsaParams.Exponent,
        D = rsaParams.D, // Private exponent
        P = rsaParams.P,
        Q = rsaParams.Q,
        DP = rsaParams.DP,
        DQ = rsaParams.DQ,
        QI = rsaParams.InverseQ,
        Id = Guid.NewGuid().ToString()
    };

    // Import the key
    key = await keyClient.ImportKeyAsync(keyName, jsonWebKey);

    // Retrieve the key
    key = await keyClient.GetKeyAsync(keyName);

    //============================Signing===================================//

    var signingSecurityKey = new RsaSecurityKey(rsaKey) { KeyId = key.Key.Id, CryptoProviderFactory = new AzureKeyVaultCryptoProviderFactory(new CryptographyClient(key.Id, credential, cryptographicClientOption)) };

    var signingCredentials = new SigningCredentials(signingSecurityKey, SecurityAlgorithms.RsaSha256);

    // Define JWT claims
    var claims = new[]
    {
            new Claim(JwtRegisteredClaimNames.Sub, "user123"),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
    };

    // Create JWT token
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(claims),
        Expires = DateTime.UtcNow.AddMinutes(30),
        Issuer = "your-issuer",
        Audience = "your-audience",
        SigningCredentials = signingCredentials
    };

    string jwt = "";
    var tokenCreationHandler = new JwtSecurityTokenHandler();
    try
    {
        var token = tokenCreationHandler.CreateToken(tokenDescriptor);
        jwt = tokenCreationHandler.WriteToken(token);

        Console.WriteLine($"Generated JWT: {jwt}");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Token generation failed: {ex.Message}");
    }

    //============================Verifying===================================//

    bool isValid = false;

    var verifyingSecurityKey = new RsaSecurityKey(rsaKey) { KeyId = key.Key.Id, CryptoProviderFactory = new AzureKeyVaultCryptoProviderFactory(new CryptographyClient(key.Id, credential, cryptographicClientOption)) };


    var tokenValidationHandler = new JwtSecurityTokenHandler();

    var validationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = "your-issuer",
        ValidateAudience = true,
        ValidAudience = "your-audience",
        ValidateLifetime = true,
        IssuerSigningKey = verifyingSecurityKey,
        ValidateIssuerSigningKey = true,
        ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
        CryptoProviderFactory = verifyingSecurityKey.CryptoProviderFactory // Use our custom crypto provider
    };

    try
    {
        tokenValidationHandler.ValidateToken(jwt, validationParameters, out SecurityToken validatedToken);
        isValid = true; // Token is valid
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Token validation failed: {ex.Message}");
        isValid = false; // Token is invalid
    }

    Console.WriteLine($"Is JWT valid? {isValid}");
}
catch (Exception ex)
{
    Console.WriteLine($"Error validating key: {ex.Message}");
}

public class CustomSignatureProvider : AsymmetricSignatureProvider
{
    private readonly CryptographyClient _cryptographyClient;

    public CustomSignatureProvider(CryptographyClient cryptographyClient,
                                   SecurityKey key,
                                   string algorithm) : base(key, algorithm)
    {
        _cryptographyClient = cryptographyClient;
    }

    public override byte[] Sign(byte[] input)
    {
        if (input == null || input.Length == 0)
        {
            throw new ArgumentNullException(nameof(input));
        }

        var result = _cryptographyClient.SignData(GetKeyVaultAlgorithm(Algorithm), input);

        return result.Signature;
    }

    public override bool Verify(byte[] input, byte[] signature)
    {
        if (input == null || input.Length == 0)
        {
            throw new ArgumentNullException(nameof(input));
        }

        if (signature == null || signature.Length == 0)
        {
            throw new ArgumentNullException(nameof(signature));
        }

        var verificationResult = _cryptographyClient.VerifyData(GetKeyVaultAlgorithm(Algorithm), input, signature);
        return verificationResult.IsValid;
    }

    protected override void Dispose(bool disposing)
    {
    }

    private static SignatureAlgorithm GetKeyVaultAlgorithm(string algorithm)
    {
        return algorithm switch
        {
            SecurityAlgorithms.RsaSha256 => SignatureAlgorithm.RS256,
            _ => throw new NotImplementedException(),
        };
    }
}

public class AzureKeyVaultCryptoProviderFactory : CryptoProviderFactory
{
    private readonly CryptographyClient _cryptographyClient;

    public AzureKeyVaultCryptoProviderFactory(CryptographyClient cryptographyClient)
    {
        _cryptographyClient = cryptographyClient;
    }

    public override SignatureProvider CreateForSigning(SecurityKey key, string algorithm)
    {
        return new CustomSignatureProvider(_cryptographyClient, key, algorithm);
    }

    public override SignatureProvider CreateForVerifying(SecurityKey key, string algorithm)
    {
        return new CustomSignatureProvider(_cryptographyClient, key, algorithm);
    }
}

public class NoopCredentials : TokenCredential
{
    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        return new AccessToken("noop", DateTimeOffset.MaxValue);
    }

    public override ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        return new ValueTask<AccessToken>(GetToken(requestContext, cancellationToken));
    }
}
