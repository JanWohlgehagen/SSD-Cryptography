using System.Net;
using System.Net.Sockets;
using System.Text;
using DeezEncryption;

namespace Server
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private readonly TinyEncryptor _encryptor;
        private readonly byte[] _key;

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
            _encryptor = new TinyEncryptor();
            _key = _encryptor.GenerateAES256Key();
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            int port = 5000;
            TcpListener listener = new TcpListener(IPAddress.Any, port);

            listener.Start();
            _logger.LogInformation($"Server listening on port {port}");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    TcpClient client = await listener.AcceptTcpClientAsync();
                    _logger.LogInformation("Client connected.");
                    _ = Task.Run(() => HandleClientAsync(client, stoppingToken), stoppingToken);
                }
                catch (Exception ex)
                {
                    _logger.LogError($"Error: {ex.Message}");
                }
            }

            listener.Stop();
            _logger.LogInformation("Server has stopped.");
        }

        private async Task HandleClientAsync(TcpClient client, CancellationToken stoppingToken)
        {
            try
            {
                Console.WriteLine("INFO | SERVER | Receiving message...");
                
                NetworkStream stream = client.GetStream();
                byte[] buffer = new byte[1024];
                int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, stoppingToken);

                // Extract nonce, tag, and ciphertext from the received message
                byte[] nonce = buffer[..12];
                byte[] tag = buffer[12..28];
                byte[] ciphertext = buffer[28..bytesRead];
                
                Console.WriteLine("INFO | SERVER | Decrypting message: " + $"'{Encoding.UTF8.GetString(ciphertext)}'.");

                // Decrypt the received message
                string clientMessage = _encryptor.DecryptString(ciphertext, nonce, tag, _key);
                
                Console.WriteLine("INFO | SERVER | Decrypted message: " + $"'{clientMessage}'.");
                
                // Respond back (encrypt the response)
                string response = $"{clientMessage}";
                
                Console.WriteLine("INFO | SERVER | Sending message...");
                Console.WriteLine("INFO | SERVER | Encrypting message: " + $"'{response}'.");
                
                var (cipherResponse, nonceResponse, tagResponse) = _encryptor.EncryptString(response, _key);
                
                Console.WriteLine("INFO | SERVER | Encrypted message: " + $"'{Convert.ToBase64String(cipherResponse)}'.");

                // Send the encrypted response (combine nonce, tag, and ciphertext)
                byte[] combinedResponse = Combine(nonceResponse, tagResponse, cipherResponse);
                await stream.WriteAsync(combinedResponse, 0, combinedResponse.Length, stoppingToken);

                client.Close();
            }
            catch (Exception ex)
            {
                _logger.LogError($"Client handling error: {ex.Message}");
            }
        }

        // Helper method to combine nonce, tag, and ciphertext into a single array
        private byte[] Combine(byte[] nonce, byte[] tag, byte[] ciphertext)
        {
            byte[] combined = new byte[nonce.Length + tag.Length + ciphertext.Length];
            Buffer.BlockCopy(nonce, 0, combined, 0, nonce.Length);
            Buffer.BlockCopy(tag, 0, combined, nonce.Length, tag.Length);
            Buffer.BlockCopy(ciphertext, 0, combined, nonce.Length + tag.Length, ciphertext.Length);
            return combined;
        }
    }
}
