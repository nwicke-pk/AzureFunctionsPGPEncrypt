using System.IO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using PgpCore;
using System.Threading.Tasks;
using Microsoft.Azure.KeyVault.Models;
using System.Net.Http;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.KeyVault;
using System;
using System.Text;
using System.Collections.Concurrent;
using Microsoft.AspNetCore.Http.Internal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using AzureFunctionsPGPService;
using Newtonsoft.Json;

namespace AzureFunctionsPGPEncrypt
{
    public static class PGPService
    {
        private static readonly HttpClient client = new HttpClient();
        private static ConcurrentDictionary<string, string> secrets = new ConcurrentDictionary<string, string>();

        [FunctionName(nameof(PGPService))]
        public static async Task<IActionResult> RunAsync(
             [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] HttpRequest req,
            // [HttpTrigger(AuthorizationLevel.Function, "post", Route = null)] PGPRequest req,
            ILogger log)
        {
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


            // read the contents of the posted data into a string
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();

            // use Json.NET to deserialize the posted JSON into a C# dynamic object
            dynamic body = JsonConvert.DeserializeObject(requestBody);

            string containerName = body.container;
            string sourceFileName = body.sourceFile;
            string destinationFileName = body.destinationFile;
            string action = body.action;
            string passPhrase = body.passPhrase;
            string keySecretID = body.key;
            string keyBase64;

            log.LogInformation($"Started with action = {action ?? "null - default to encrypt"}.");

            if (keySecretID == null)
            {
                return new BadRequestObjectResult("Please pass a base64 encoded key vault secret identifier on the query string. public key for encryption and private key fro decription.");
            }

            try
            {
                keyBase64 = await GetKeyAsync(keySecretID);
            }
            catch (KeyVaultErrorException e) when (e.Body.Error.Code == "SecretNotFound")
            {
                return new NotFoundResult();
            }
            catch (KeyVaultErrorException e) when (e.Body.Error.Code == "Forbidden")
            {
                return new UnauthorizedResult();
            }
            

            byte[] data = Convert.FromBase64String(keyBase64);
            string key = Encoding.UTF8.GetString(data);
            req.EnableRewind(); //Make RequestBody Stream seekable

            log.LogInformation($"retrieved key");

            BlobHandler blobHandler = new BlobHandler(log, containerName, connectionString, sourceFileName, destinationFileName);
            Task<Stream> getBlobTask = blobHandler.ReadInputFile();
            getBlobTask.Result.Position = 0;
            log.LogInformation($"{getBlobTask.Result.Length} read from blob.");

            Stream outData = new MemoryStream();
            
            action = action.ToLower();
            if (action == "decrypt")
            {
                outData = await DecryptAsync(getBlobTask.Result, key, passPhrase);
                log.LogInformation($"{outData.Length} of decrypted data.");
            }
            else  //default to encrypt
            {
                outData = await EncryptAsync(getBlobTask.Result, key);
                log.LogInformation($"{outData.Length} of encrypted data.");
            }
            try
            {
                Task writeBlobTask = blobHandler.WriteOutputBlob(outData);
            }
            catch (Exception ex)
            {
                log.LogError($"Error writing file! - {ex}");
                return new BadRequestObjectResult($"Error writing file {ex}");
            }
            return new OkObjectResult(destinationFileName);
        }

        private static async Task<string> GetKeyAsync(string secretIdentifier)
        {
            if (!secrets.ContainsKey(secretIdentifier))
            {
                var azureServiceTokenProvider = new AzureServiceTokenProvider();
                var authenticationCallback = new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback);
                var kvClient = new KeyVaultClient(authenticationCallback, client);

                SecretBundle secretBundle = await kvClient.GetSecretAsync(secretIdentifier);
                secrets[secretIdentifier] = secretBundle.Value;
            }
            return secrets[secretIdentifier];
        }

        private static async Task<Stream> EncryptAsync(Stream inputStream, string publicKey)
        {
            using (PGP pgp = new PGP())
            {
                Stream outputStream = new MemoryStream();
                try
                {
                    using (inputStream)
                    using (Stream publicKeyStream = GenerateStreamFromString(publicKey))
                    {
                        await pgp.EncryptStreamAsync(inputStream, outputStream, publicKeyStream, true, true);
                        outputStream.Seek(0, SeekOrigin.Begin);
                        return outputStream;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    Console.ReadLine();
                    throw;
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



    }
}
