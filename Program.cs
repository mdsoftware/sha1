using System;
using System.IO;
using System.Security.Cryptography;

namespace test
{
    class Program
    {


        static void Main(string[] args)
        {
            var rnd = new Random();

            for (int i = 0; i < 10000; i++)
            {
                var l = rnd.Next(50000);
                var buffer = new byte[l];
                for (int j = 0; j < l; j++)
                    buffer[j] = (byte)(rnd.Next() & 0xff);


                var h0 = new Hashing.SHA1Hash();
                var hash = h0.Compute(buffer, buffer.Length);

                var h1 = new SHA1CryptoServiceProvider();
                byte[] hashed = h1.ComputeHash(buffer);

                var s0 = ToHex(hash);
                Console.WriteLine(s0);
                var s1 = ToHex(hashed);
                Console.WriteLine(s1);

                Console.WriteLine("{0} {1}", i + 1, s0 == s1 ? "OK" : "ERROR");

                if (s0 != s1)
                    break;

            }

            Console.Write(">>> PRESS ENTER");
            Console.ReadLine();
        }

        private static string ToHex(byte[] buf)
        {
            var s = String.Empty;
            foreach (var b in buf)
                s += b.ToString("x2");
            return s;
        }
    }
}
