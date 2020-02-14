using System.IO;
using System.Threading.Tasks;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Blob;
using Microsoft.Extensions.Logging;


namespace AzureFunctionsPGPEncrypt
{
     internal class BlobHandler
    {
        private readonly ILogger _log;
        private CloudStorageAccount _storageAccount;
        private CloudBlobContainer _storageContainer;
        private CloudBlobClient _blobClient;
        readonly string _inputFileName, _outputFileName;

        public BlobHandler(ILogger log, string containerName, string storageAccountConnectionstring, string inputFileName, string outputFileName)
        {
            try
            {
                _log = log;
                _storageAccount = CloudStorageAccount.Parse(storageAccountConnectionstring);
                _blobClient = _storageAccount.CreateCloudBlobClient();
                _storageContainer = _blobClient.GetContainerReference(containerName);
                _inputFileName = inputFileName;
                _outputFileName = outputFileName;
            }
            catch (StorageException e)
            {
                log.LogCritical($"BlobHandler StorageException  - {e}.");
                throw;
            }
        }


        public async Task<Stream> ReadInputFile()
        {
            CloudBlockBlob cloudBlockBlob = _storageContainer.GetBlockBlobReference(_inputFileName);

            MemoryStream memoryStream = new MemoryStream();

            await cloudBlockBlob.DownloadToStreamAsync(memoryStream);
            memoryStream.Position = 0;
            return memoryStream;
            /* using (StreamReader reader = new StreamReader(memoryStream))
             {
                 memoryStream.Position = 0;
                 return (reader == null) ? null : await reader.ReadToEndAsync();
             }
             */

        }

       
        public async Task WriteOutputBlob(Stream rawData)
        {
            try
            {
                //createing blob object in memory
                CloudBlockBlob blob = _storageContainer.GetBlockBlobReference(_outputFileName);

                // Writing to the blob 
                await blob.UploadFromStreamAsync(rawData);
                //await blob.UploadTextAsync(rawData);
            }
            catch ( StorageException ex)
            {
                _log.LogError($"Error writing blob - {ex}");
                throw;
            }
        }
    }
}
