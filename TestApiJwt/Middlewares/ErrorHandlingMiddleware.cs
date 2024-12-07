using Microsoft.AspNetCore.Http;
using System;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;

namespace TestApiJwt.Middlewares
{
    public class ErrorHandlingMiddleware : IMiddleware
    {
        public async Task InvokeAsync(HttpContext context, RequestDelegate next)
        {
            try
            {
                // Proceed to the next middleware in the pipeline
                await next(context);
            }
            catch (Exception ex)
            {
                // Handle the exception globally
                await HandleExceptionAsync(context, ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            // Log the exception here if needed (e.g., using a logging framework)
            // Example: _logger.LogError(exception, "An unexpected error occurred");

            context.Response.ContentType = "application/json";
            context.Response.StatusCode = (int)HttpStatusCode.InternalServerError;

            var response = new
            {
                StatusCode = context.Response.StatusCode,
                Message = "An unexpected error occurred.",
                // Detailed = exception.Message // Avoid sending detailed messages in production for security reasons
            };

            // Serialize the response to JSON
            var jsonResponse = JsonSerializer.Serialize(response);

            await context.Response.WriteAsync(jsonResponse);
        }
    }
}
