using System.IO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.WebJobs.Host;
using PgpCore;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault.Models;
using System.Net.Http;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.KeyVault;
using System;
using System.Text;
using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using AzureFunctionsPGPEncrypt;
using Microsoft.Extensions.Configuration;


namespace AzureFunctionsPGPDecrypt
{
    public static class PGPDecrypt
    {
        private static readonly HttpClient client = new HttpClient();
        private static ConcurrentDictionary<string, string> secrects = new ConcurrentDictionary<string, string>();

        [FunctionName(nameof(PGPDecrypt))]
        public static async Task<IActionResult> RunAsync(
            [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)]
        HttpRequest req, ILogger log)
        {
            log.LogInformation($"C# HTTP trigger function {nameof(PGPDecrypt)} processed a request.");

            var config = new ConfigurationBuilder()
            .SetBasePath(AppContext.BaseDirectory)
            .AddJsonFile("local.settings.json", optional: true, reloadOnChange: true)
            .AddEnvironmentVariables()
            .Build();

            var connectionString = config["storageConnectionString"];

            if (string.IsNullOrEmpty(connectionString))
            {
                log.LogError($"Error storageConnectionString not found!");
                return (new BadRequestObjectResult("Storage Connection String Missing from configuration."));
            }


            string privateKeySecretId = req.Query["privatekeysecretid"];
            string passPhraseSecretId = req.Query["passphrasesecretid"];
            string containerName = req.Query["container"];
            string sourceFileName = req.Query["sourceFile"];
            string destinationFileName = req.Query["destinationFile"];

            if (privateKeySecretId == null)
            {
                return new BadRequestObjectResult("Please pass a private key secret identifier on the query string");
            }

            string privateKey;
            string passPhrase = null;
            try
            {
                privateKey = await GetFromKeyVaultAsync(privateKeySecretId);
                if (passPhraseSecretId != null)
                {
                    passPhrase = await GetFromKeyVaultAsync(passPhraseSecretId);
                }
            }
            catch (KeyVaultErrorException e) when (e.Body.Error.Code == "SecretNotFound")
            {
                return new NotFoundResult();
            }
            catch (KeyVaultErrorException e) when (e.Body.Error.Code == "Forbidden")
            {
                return new UnauthorizedResult();
            }

            BlobHandler blobHandler = new BlobHandler(log, containerName, connectionString, sourceFileName, destinationFileName);
            Task<Stream> getBlobTask = blobHandler.ReadInputFile();
            getBlobTask.Result.Position = 0;
            log.LogInformation($"{getBlobTask.Result.Length} read from blob.");

            Stream decryptedData = await DecryptAsync(getBlobTask.Result, privateKey, passPhrase);

            log.LogInformation($"{decryptedData.Length} of dencrypted data.");

            Task writeBlobTask = blobHandler.WriteOutputBlob(decryptedData);


            return new OkObjectResult(destinationFileName);
        }

        private static async Task<string> GetFromKeyVaultAsync(string secretIdentifier)
        {
            if (!secrects.ContainsKey(secretIdentifier))
            {
                var azureServiceTokenProvider = new AzureServiceTokenProvider();
                var authenticationCallback = new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback);
                var kvClient = new KeyVaultClient(authenticationCallback, client);

                SecretBundle secretBundle = await kvClient.GetSecretAsync(secretIdentifier);
                byte[] data = Convert.FromBase64String(secretBundle.Value);
                secrects[secretIdentifier] = Encoding.UTF8.GetString(data);
            }
            return secrects[secretIdentifier];
        }

        private static async Task<Stream> DecryptAsync(Stream inputStream, string privateKey, string passPhrase)
        {
            using (PGP pgp = new PGP())
            {
                Stream outputStream = new MemoryStream();
                try
                {
                    using (inputStream)
                    using (Stream privateKeyStream = GenerateStreamFromString(privateKey))
                    {
                        await pgp.DecryptStreamAsync(inputStream, outputStream, privateKeyStream, passPhrase);
                        outputStream.Seek(0, SeekOrigin.Begin);
                        return outputStream;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    Console.ReadLine();
                    return outputStream;
                }
            }
        }

        private static Stream GenerateStreamFromString(string s)
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write(s);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }
    }
}
