using System.Globalization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace TryAuth0.Web.Controllers;

public class AccountController : Controller
{
    private readonly ILogger<AccountController> _logger;

    public AccountController(ILogger<AccountController> logger)
    {
        _logger = logger;
    }

    public Task Login(string returnUrl = "/")
    {
        return HttpContext.ChallengeAsync("Auth0", new AuthenticationProperties { RedirectUri = returnUrl });
    }

    [Authorize]
    public async Task Logout()
    {
        await HttpContext.SignOutAsync("Auth0", new AuthenticationProperties
        {
            // Indicate here where Auth0 should redirect the user after a logout.
            // Note that the resulting absolute Uri must be added to the
            // **Allowed Logout URLs** settings for the app.
            RedirectUri = Url.Action("Index", "Home")
        });
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    }

    public async Task<IResult> Claims()
    {
        // Inside one of your controller actions

        if (User.Identity!.IsAuthenticated)
        {
            string? accessToken = await HttpContext.GetTokenAsync("access_token");
            
            // if you need to check the Access Token expiration time, use this value
            // provided on the authorization response and stored.
            // do not attempt to inspect/decode the access token
            DateTime accessTokenExpiresAt = DateTime.Parse(
                await HttpContext.GetTokenAsync("expires_at") ?? DateTime.MaxValue.ToString("o"), 
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind);
                
            string? idToken = await HttpContext.GetTokenAsync("id_token");

            _logger.LogDebug("IdToken: {0}", idToken);
            _logger.LogDebug("AccessToken: {0}", accessToken);
            _logger.LogDebug("Expire: {0}", accessTokenExpiresAt);

            // Now you can use them. For more info on when and how to use the
            // Access Token and ID Token, see https://auth0.com/docs/tokens

            return Results.Ok(new { idToken, accessToken, accessTokenExpiresAt });
        }

        return Results.Unauthorized();
    }
}
