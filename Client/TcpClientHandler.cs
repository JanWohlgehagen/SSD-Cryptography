using System.Net.Sockets;
using System.Text;
using DeezEncryption;

public class TcpClientHandler
{
    private readonly TcpClient _client;
    private readonly NetworkStream _stream;
    private readonly TinyEncryptor _encryptor;
    private readonly byte[] _key;

    public TcpClientHandler(string serverIp, int serverPort)
    {
        _client = new TcpClient(serverIp, serverPort);
        _stream = _client.GetStream();

        // Initialize the encryptor and generate a key
        _encryptor = new TinyEncryptor();
        _key = _encryptor.GenerateAES256Key();
    }

    public async Task SendMessageAsync(string message)
    {
        Console.WriteLine("INFO | CLIENT | Sending message... " + $"'{message}'.");
        Console.WriteLine("INFO | CLIENT | Encrypting message: " + $"'{message}'.");
        
        // Encrypt the message
        var (ciphertext, IV, tag) = _encryptor.EncryptString(message, _key);
        
        Console.WriteLine("INFO | CLIENT | Encrypted message: " + $"'{Convert.ToBase64String(ciphertext)}'.");

        // Combine ciphertext, IV, and tag into one byte array for transmission
        byte[] combinedMessage = Combine(IV, tag, ciphertext);
        


        // Send the combined encrypted message
        await _stream.WriteAsync(combinedMessage, 0, combinedMessage.Length);
    }

    public async Task<string> ReceiveMessageAsync()
    {
        Console.WriteLine("INFO | CLIENT | Receiving message...");
        // Buffer to receive the server's encrypted response
        byte[] buffer = new byte[1024];
        int bytesRead = await _stream.ReadAsync(buffer, 0, buffer.Length);

        // Extract the IV, tag, and ciphertext from the received message
        byte[] IV = buffer[..12];
        byte[] tag = buffer[12..28];
        byte[] ciphertext = buffer[28..bytesRead];
        
        
        Console.WriteLine("INFO | CLIENT | Decrypting message: " + $"'{Encoding.UTF8.GetString(ciphertext)}'.");

        // Decrypt the received message
        string decryptedMessage = _encryptor.DecryptString(ciphertext, IV, tag, _key);
        
        Console.WriteLine("INFO | CLIENT | Decrypted message: " + $"'{decryptedMessage}'.");

        return decryptedMessage;
    }

    public void Close()
    {
        _stream.Close();
        _client.Close();
    }

    // Helper method to combine IV, tag, and ciphertext into a single array
    private byte[] Combine(byte[] IV, byte[] tag, byte[] ciphertext)
    {
        byte[] combined = new byte[IV.Length + tag.Length + ciphertext.Length];
        Buffer.BlockCopy(IV, 0, combined, 0, IV.Length);
        Buffer.BlockCopy(tag, 0, combined, IV.Length, tag.Length);
        Buffer.BlockCopy(ciphertext, 0, combined, IV.Length + tag.Length, ciphertext.Length);
        return combined;
    }
}
