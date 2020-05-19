using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace DES
{
    class Program
    {
        static void Main(string[] args)
        {
            Encryptor encryptor = new Encryptor();
            var input = "ABCDABCD";
            var key = "01234567";
            byte[] bytes = Encoding.Default.GetBytes(input);
            var encrypted = encryptor.Encrypt(bytes, Encoding.Default.GetBytes(key));
            var decrypted = encryptor.Decrypt(encrypted, Encoding.Default.GetBytes(key));

            Console.WriteLine(Encoding.Default.GetString(decrypted));
            Console.ReadKey();
        }
    }
}
