namespace ApiKeyAuthentication.Middlewares
{
    public class ApiKeyMiddleware
    {
        private readonly RequestDelegate _requestDelegate;
        private const string ApiKey = "X-API-KEY";

        public ApiKeyMiddleware(RequestDelegate requestDelegate)
        {
            _requestDelegate = requestDelegate;
        }

        public async Task Invoke(HttpContext context)
        {
            if (!context.Request.Headers.TryGetValue(ApiKey, out var apiKeyVal))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Api Key not found!");
            }

            var appSettings = context.RequestServices.GetRequiredService<IConfiguration>();
            var apiKey = appSettings.GetValue<string>(ApiKey);
            if (!apiKey.Equals(apiKeyVal))
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Unauthorized client");
            }

            await _requestDelegate(context);
        }
    }
}
