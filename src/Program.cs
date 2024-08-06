using CommandLine;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace WFPakCryptCLI
{
    public class Program
    {
        [DllImport("WFPakCrypt.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern void InitRSA(IntPtr rsa, int length);
        [DllImport("WFPakCrypt.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern bool DecryptPak(string fin, string fout, bool olderSupport);

        public class Options
        {
            [Option('k', "rsa", Required = true, Default = "ru.txt", HelpText = "Set the RSA key file.")]
            public string RSAFile { get; set; }
            [Option('i', "input", Required = true, HelpText = "Set the input file or directory.")]
            public string Input { get; set; }
            [Option('o', "output", Required = false, HelpText = "Specify the output file or directory.")]
            public string Output { get; set; }
            [Option('r', "recursive", Required = false, HelpText = "Set this to include all subdirectories.")]
            public bool IsRecursive { get; set; }
        }

        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;

            Parser.Default.ParseArguments<Options>(args)
                .WithParsed(RunOptions);

            Console.ReadLine();
        }

        static void RunOptions(Options o)
        {
            byte[] rsaKeyData = ParseRSAKey(o.RSAFile);

            if (rsaKeyData.Length != 140)
            {
                Console.WriteLine("Invalid RSA key (length of public key is 140).");
                return;
            }


            List<string> files;

            if (Directory.Exists(o.Input))
            {
                files = Directory.GetFiles(o.Input, "*.pak",
                    o.IsRecursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly)
                    .ToList();
            }
            else if (File.Exists(o.Input))
            {
                files = new List<string> { o.Input };
            }
            else
            {
                Console.WriteLine("Invalid input file extension!");
                return;
            }

            IntPtr pKey = GCHandle.Alloc(rsaKeyData, GCHandleType.Pinned).AddrOfPinnedObject();
            InitRSA(pKey, rsaKeyData.Length);
            Console.WriteLine($"RSA key initialized.");

            int decryptedLength = 0;
            foreach (var file in files)
            {
                DecryptPak(file, file + ".zip", false);
                Console.WriteLine($"[{++decryptedLength}/{files.Count}] '{file}' decrypted.");
            }

            Console.WriteLine("Done.");
        }

        static byte[] ParseRSAKey(string keyFile)
        {
            string str = File.ReadAllText(keyFile, Encoding.UTF8).Replace(Environment.NewLine, string.Empty).Replace(" ", string.Empty);
            return StringToByteArray(str);
        }

        static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
