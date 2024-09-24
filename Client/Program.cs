Console.WriteLine("Hello, World!");

await MainThread();

static async Task MainThread()
{
    Console.WriteLine("Client is starting...");

    string serverIp = "127.0.0.1";
    int serverPort = 5000;

    try
    {
        TcpClientHandler clientHandler = new TcpClientHandler(serverIp, serverPort);

        Console.WriteLine("Connected to the server.");

        while (true)
        {
            // Get user input
            Console.Write("Enter a message to send (or 'exit' to quit): ");
            string userInput = Console.ReadLine();

            if (userInput?.ToLower() == "exit")
                break;

            // Encrypt and send the message
            await clientHandler.SendMessageAsync(userInput);

            // Receive and decrypt the response
            string serverResponse = await clientHandler.ReceiveMessageAsync();
            Console.WriteLine($"Server replied: {serverResponse}");
        }

        clientHandler.Close();
        Console.WriteLine("Client has stopped.");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error: {ex.Message}");
    }
}
