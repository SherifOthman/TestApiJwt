namespace TestApiJwt.Helpers;

public class JWT
{
    public string Key { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Aduience { get; set; } = string.Empty;
    public int DurationInDays { get; set; }
}
