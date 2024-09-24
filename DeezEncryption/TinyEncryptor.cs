using System.Security.Cryptography;
using System.Text;

namespace DeezEncryption;

public class TinyEncryptor
{
    // Encrypts a string and returns the ciphertext, nonce, and tag
    public (byte[] ciphertext, byte[] IV, byte[] tag) EncryptString(string input, byte[] key)
    {
        // Create a new AES GCM object with the provided key
        using AesGcm aes = new AesGcm(key, AesGcm.TagByteSizes.MaxSize);
        
        // Generate a random IV
        var IV = new byte[AesGcm.NonceByteSizes.MaxSize];
        RandomNumberGenerator.Fill(IV);
        
        // Convert the input string to bytes
        var plaintextBytes = Encoding.UTF8.GetBytes(input);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize]; // Authentication tag
        
        aes.Encrypt(IV, plaintextBytes, ciphertext, tag);
        
        return (ciphertext, IV, tag);
    }
    
    public string DecryptString(byte[] ciphertext, byte[] IV, byte[] tag, byte[] key)
    {
        using AesGcm aes = new AesGcm(key, tag.Length);
        
        var plaintextBytes = new byte[ciphertext.Length];
        
        aes.Decrypt(IV, ciphertext, tag, plaintextBytes);
        
        // Convert the decrypted bytes back into a string
        string decryptedMessage = Encoding.UTF8.GetString(plaintextBytes);
        
        return decryptedMessage;
    }
}